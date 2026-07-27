from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import tomllib
from typing import Any, BinaryIO
import unicodedata

from .host_policy import HostPolicy, HostPolicyError, load_host_policy

NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
VARIABLE_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
DOMAIN_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}[a-z0-9]\Z")
LABEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}\Z")
OP_REFERENCE_PATTERN = re.compile(
    r"op://[A-Za-z0-9._~-]+/[A-Za-z0-9._~-]+/"
    r"(?:[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+\Z"
)
DOTENV_LINE_PATTERN = re.compile(
    r"(?P<variable>[A-Za-z_][A-Za-z0-9_]*)=(?P<reference>op://[^\s]+)\Z"
)

COMMON_FIELDS = {"schema_version", "kind", "name", "description"}
LEAF_POLICY_FIELDS = COMMON_FIELDS | {
    "auth_kind",
    "providers",
    "capabilities",
    "risk",
    "identity_probe",
    "interactive",
    "max_duration_seconds",
}
LEAF_FIELDS = LEAF_POLICY_FIELDS | {
    "env_files", "injected_files", "clear_variables", "service_account",
}
LEGACY_LEAF_FIELDS = LEAF_FIELDS - {"auth_kind"}
AWS_LEAF_FIELDS = LEAF_POLICY_FIELDS | {
    "role_arn", "region", "session_duration_seconds",
}
COMPOSITE_FIELDS = COMMON_FIELDS | {"includes"}
INJECTED_FILE_FIELDS = {"template", "target_env"}
SERVICE_ACCOUNT_FIELDS = {"account", "vaults"}

SUPPORTED_PROVIDERS = frozenset({"aws", "github", "gcloud", "azure", "omnistrate"})
SUPPORTED_CAPABILITIES = frozenset(
    {
        "identity-read",
        "repository-read",
        "repository-write",
        "artifact-build",
        "artifact-publish",
        "administration",
    }
)
SUPPORTED_PROBES = {
    "aws-caller": "aws",
    "github-user": "github",
    "gcloud-account": "gcloud",
    "azure-account": "azure",
    "omnistrate-user": "omnistrate",
}
RISK_ORDER = {
    "development": 0,
    "build": 1,
    "production": 2,
    "publish": 3,
    "administration": 4,
}
MAX_DURATION_SECONDS = 86_400

# Bundle-controlled names are resolved by `op run` before the isolated launcher
# starts. Keep this policy explicit and fail closed for interpreter/loader
# families and every selector owned by the wrapper.
RESERVED_BUNDLE_ENV_PREFIXES = (
    "LD_", "DYLD_", "XDG_", "PYTHON", "PERL", "RUBY", "NODE_",
    "DBUS_", "SYSTEMD_", "OP_",
)
RESERVED_BUNDLE_ENV_NAMES = frozenset(
    {
        "PATH", "HOME", "TMPDIR", "ENV", "BASH_ENV", "SHELLOPTS",
        "GCONV_PATH", "GLIBC_TUNABLES", "LOCPATH", "NLSPATH",
        "CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS",
        "GEM_HOME", "GEM_PATH", "LUA_PATH", "LUA_CPATH", "PHP_INI_SCAN_DIR",
        "OP_SERVICE_ACCOUNT_TOKEN", "OP_RUN_NO_MASKING",
        "DBUS_SESSION_BUS_ADDRESS", "NOTIFY_SOCKET", "JOURNAL_STREAM",
        "SYSTEMD_EXEC_PID", "INVOCATION_ID", "ACCESS_PRIVATE_RUNTIME",
        "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
        "AWS_EC2_METADATA_DISABLED", "GH_CONFIG_DIR", "CLOUDSDK_CONFIG",
        "AZURE_CONFIG_DIR", "OMNISTRATE_CONFIG_DIR", "PIP_CACHE_DIR",
        "UV_CACHE_DIR",
    }
)


class BundleError(ValueError):
    """A bundle registry entry is absent, untrusted, or invalid."""


@dataclass(frozen=True)
class ServiceAccountConstraint:
    account: str
    vaults: tuple[str, ...]


@dataclass(frozen=True)
class InjectedFile:
    template: Path
    target_env: str


@dataclass(frozen=True)
class Bundle:
    name: str
    kind: str
    schema_version: int
    description: str
    providers: tuple[str, ...]
    capabilities: tuple[str, ...]
    risk: str
    env_files: tuple[Path, ...]
    injected_files: tuple[InjectedFile, ...]
    clear_variables: tuple[str, ...]
    identity_probes: tuple[str, ...]
    interactive: bool
    max_duration_seconds: int
    service_account: ServiceAccountConstraint | None
    auth_kind: str
    aws_role_arn: str | None
    aws_region: str | None
    aws_session_duration_seconds: int | None
    aws_profile_name: str | None
    includes: tuple[str, ...]
    variables: dict[str, str]
    environment_names: frozenset[str]
    leaf_names: frozenset[str]


def default_root() -> Path:
    return Path.home() / ".config" / "access"


def _has_control_characters(value: str) -> bool:
    return any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        for character in value
    )


class BundleRegistry:
    def __init__(
        self,
        root: Path | str | None = None,
        *,
        _host_policy: HostPolicy | None = None,
    ) -> None:
        candidate = default_root() if root is None else Path(root)
        if not candidate.is_absolute():
            raise BundleError("trusted root must be an absolute path")
        self.root = candidate.absolute()
        self._effective_uid = os.geteuid()
        self._host_policy = _host_policy
        try:
            root_stat = self.root.lstat()
        except OSError as error:
            raise BundleError("trusted root is unavailable") from error
        if stat.S_ISLNK(root_stat.st_mode):
            raise BundleError("trusted root must not be a symlink")
        self._reject_symlinked_ancestors()
        self._validate_stat(root_stat, kind="trusted root", require_directory=True)

    def _reject_symlinked_ancestors(self) -> None:
        for ancestor in self.root.parents:
            try:
                result = ancestor.lstat()
            except OSError as error:
                raise BundleError("trusted root ancestor is unavailable") from error
            if stat.S_ISLNK(result.st_mode):
                raise BundleError("trusted root ancestor must not be a symlink")

    def _validate_root(self) -> None:
        try:
            root_stat = self.root.lstat()
        except OSError as error:
            raise BundleError("trusted root is unavailable") from error
        if stat.S_ISLNK(root_stat.st_mode):
            raise BundleError("trusted root must not be a symlink")
        self._reject_symlinked_ancestors()
        self._validate_stat(root_stat, kind="trusted root", require_directory=True)

    def _validate_stat(
        self, result: os.stat_result, *, kind: str, require_directory: bool = False
    ) -> None:
        expected_type = stat.S_ISDIR if require_directory else stat.S_ISREG
        if not expected_type(result.st_mode):
            expected = "directory" if require_directory else "regular file"
            raise BundleError(f"{kind} must be a {expected}")
        if result.st_uid != self._effective_uid:
            raise BundleError(f"{kind} must be owned by the effective user")
        if result.st_mode & 0o022:
            raise BundleError(f"{kind} must not be group/world writable")

    def _validate_directory(self, path: Path, *, kind: str) -> None:
        try:
            result = path.lstat()
        except OSError as error:
            raise BundleError(f"{kind} directory is unavailable") from error
        if stat.S_ISLNK(result.st_mode):
            raise BundleError(f"{kind} directory must not be a symlink")
        self._validate_stat(result, kind=f"{kind} directory", require_directory=True)

    def _reject_repository_root(self) -> None:
        for directory in (self.root, *self.root.parents):
            marker = directory / ".git"
            try:
                marker_stat = marker.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                raise BundleError("cannot validate repository boundary") from error
            # Directories mark normal checkouts and regular files mark linked
            # worktrees/submodules. Any other marker type is ambiguous.
            raise BundleError("bundle registry must not be repository-controlled")

    def _relative_path(self, relative: str, *, kind: str) -> Path:
        if _has_control_characters(relative):
            raise BundleError(f"{kind} path contains a control character")
        path = Path(relative)
        if path.is_absolute():
            raise BundleError(f"{kind} path must be relative to the trusted root")
        try:
            resolved = (self.root / path).resolve(strict=False)
        except OSError as error:
            raise BundleError(f"{kind} path cannot be resolved") from error
        if not resolved.is_relative_to(self.root):
            raise BundleError(f"{kind} path escapes the trusted root")

        current = self.root
        for component in path.parts[:-1]:
            if component in {"", ".", ".."}:
                raise BundleError(f"{kind} path is not canonical")
            current /= component
            self._validate_directory(current, kind=kind)
        return self.root / path

    def _open_file(self, relative: str, *, kind: str) -> BinaryIO:
        path = self._relative_path(relative, kind=kind)
        try:
            path_stat = path.lstat()
        except OSError as error:
            raise BundleError(f"{kind} file is unavailable") from error
        if stat.S_ISLNK(path_stat.st_mode):
            try:
                resolved = path.resolve(strict=True)
            except OSError as error:
                raise BundleError(f"{kind} symlink is invalid") from error
            if not resolved.is_relative_to(self.root):
                raise BundleError(f"{kind} path escapes the trusted root")
            raise BundleError(f"{kind} file must not be a symlink")

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise BundleError(f"{kind} file cannot be opened safely") from error
        try:
            opened_stat = os.fstat(descriptor)
            self._validate_stat(opened_stat, kind=f"{kind} file")
            if (
                opened_stat.st_dev != path_stat.st_dev
                or opened_stat.st_ino != path_stat.st_ino
            ):
                raise BundleError(f"{kind} file changed while being opened")
            return os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise

    def _read_bytes(self, relative: str, *, kind: str) -> bytes:
        try:
            with self._open_file(relative, kind=kind) as stream:
                return stream.read()
        except BundleError:
            raise
        except OSError as error:
            raise BundleError(f"{kind} file cannot be read") from error

    def names(self) -> list[str]:
        self._validate_root()
        self._reject_repository_root()
        bundles_dir = self.root / "bundles"
        self._validate_directory(bundles_dir, kind="bundles")
        names: list[str] = []
        try:
            with os.scandir(bundles_dir) as entries:
                for entry in entries:
                    if (
                        not entry.name.endswith(".toml")
                        or not NAME_PATTERN.fullmatch(entry.name[:-5])
                    ):
                        raise BundleError(f"invalid bundle entry: {entry.name!r}")
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        raise BundleError("bundle entry cannot be inspected") from error
                    if not stat.S_ISREG(entry_stat.st_mode):
                        raise BundleError(f"invalid bundle entry: {entry.name!r}")
                    self._validate_stat(entry_stat, kind="bundle manifest")
                    names.append(entry.name[:-5])
        except BundleError:
            raise
        except OSError as error:
            raise BundleError("bundles directory cannot be read") from error
        return sorted(names)

    def load(self, name: str) -> Bundle:
        self._validate_root()
        self._reject_repository_root()
        self._validate_directory(self.root / "bundles", kind="bundles")
        return self._load(name, stack=())

    def _load(self, name: str, stack: tuple[str, ...]) -> Bundle:
        if not NAME_PATTERN.fullmatch(name):
            raise BundleError(f"invalid bundle name: {name!r}")
        if name in stack:
            raise BundleError(f"composite bundle cycle involving {name}")

        raw_manifest = self._read_bytes(f"bundles/{name}.toml", kind="manifest")
        try:
            manifest_text = raw_manifest.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BundleError(f"bundle {name} is not valid UTF-8") from error
        try:
            data = tomllib.loads(manifest_text)
        except tomllib.TOMLDecodeError as error:
            raise BundleError(f"bundle {name} contains invalid TOML") from error
        if not isinstance(data, dict):
            raise BundleError(f"bundle {name} must contain a TOML table")

        self._validate_common(data, name)
        kind = data["kind"]
        if kind == "leaf":
            auth_kind = data.get("auth_kind", "onepassword")
            expected = (
                AWS_LEAF_FIELDS if auth_kind == "aws-assume-role"
                else LEAF_FIELDS if "auth_kind" in data
                else LEGACY_LEAF_FIELDS
            )
            self._check_exact_fields(data, expected, "leaf bundle")
            return self._load_leaf(name, data)
        if kind == "composite":
            self._check_exact_fields(data, COMPOSITE_FIELDS, "composite bundle")
            return self._load_composite(name, data, stack)
        raise BundleError("kind must be either leaf or composite")

    def _validate_common(self, data: dict[str, Any], name: str) -> None:
        for field in COMMON_FIELDS:
            if field not in data:
                raise BundleError(f"missing field: {field}")
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise BundleError("unsupported schema_version; expected 1")
        if data["name"] != name:
            raise BundleError("bundle name must match its manifest filename")
        self._require_safe_string(data, "name")
        self._require_safe_string(data, "description")
        self._require_safe_string(data, "kind")

    def _load_leaf(self, name: str, data: dict[str, Any]) -> Bundle:
        providers = self._supported_list(
            data, "providers", SUPPORTED_PROVIDERS, label="provider"
        )
        capabilities = self._supported_list(
            data, "capabilities", SUPPORTED_CAPABILITIES, label="capability"
        )
        risk = data["risk"]
        if not isinstance(risk, str) or risk not in RISK_ORDER:
            raise BundleError("risk is not supported")
        probe = data["identity_probe"]
        if not isinstance(probe, str) or probe not in SUPPORTED_PROBES:
            raise BundleError("identity_probe is not supported")
        if SUPPORTED_PROBES[probe] not in providers:
            raise BundleError("identity_probe does not match a configured provider")
        if type(data["interactive"]) is not bool:
            raise BundleError("interactive must be a boolean")
        duration = data["max_duration_seconds"]
        if (
            type(duration) is not int
            or duration <= 0
            or duration > MAX_DURATION_SECONDS
        ):
            raise BundleError(
                f"duration must be between 1 and {MAX_DURATION_SECONDS} seconds"
            )

        auth_kind = data.get("auth_kind", "onepassword")
        if auth_kind not in {"onepassword", "aws-assume-role"}:
            raise BundleError("auth_kind is not supported")
        if auth_kind == "aws-assume-role":
            return self._load_aws_leaf(name, data, providers, capabilities, risk, probe, duration)
        env_file_names = self._string_list(data, "env_files")
        clear_variables = self._variable_list(data, "clear_variables")
        service = self._service_account(data["service_account"])
        injected_files = self._injected_files(data["injected_files"])
        env_files: list[Path] = []
        variables: dict[str, str] = {}
        environment_names: set[str] = set()
        for relative in env_file_names:
            env_files.append(self._relative_path(relative, kind="env-file"))
            incoming = self._read_env_file(relative)
            self._claim_names(environment_names, incoming, context=name)
            variables.update(incoming)
        self._claim_names(environment_names, clear_variables, context=name)
        self._claim_names(
            environment_names,
            (injected.target_env for injected in injected_files),
            context=name,
        )

        return Bundle(
            name=name,
            kind="leaf",
            schema_version=1,
            description=data["description"],
            providers=providers,
            capabilities=capabilities,
            risk=risk,
            env_files=tuple(env_files),
            injected_files=injected_files,
            clear_variables=clear_variables,
            identity_probes=(probe,),
            interactive=data["interactive"],
            max_duration_seconds=duration,
            service_account=service,
            auth_kind="onepassword",
            aws_role_arn=None,
            aws_region=None,
            aws_session_duration_seconds=None,
            aws_profile_name=None,
            includes=(),
            variables=variables,
            environment_names=frozenset(environment_names),
            leaf_names=frozenset({name}),
        )

    def _load_aws_leaf(self, name, data, providers, capabilities, risk, probe, duration):
        try:
            policy = self._host_policy or load_host_policy()
            approval = policy.approved_role(data["role_arn"], data["region"])
        except HostPolicyError as error:
            raise BundleError(str(error)) from error
        session = data["session_duration_seconds"]
        if type(session) is not int or session != approval.session_duration_seconds:
            raise BundleError("AWS role profile duration is not approved")
        if duration > approval.max_command_duration_seconds:
            raise BundleError("AWS assume-role command duration exceeds host policy")
        if providers != ("aws",) or probe != "aws-caller":
            raise BundleError("AWS assume-role bundle metadata is inconsistent")
        return Bundle(
            name=name, kind="leaf", schema_version=1, description=data["description"],
            providers=providers, capabilities=capabilities, risk=risk,
            env_files=(), injected_files=(), clear_variables=(),
            identity_probes=(probe,), interactive=data["interactive"],
            max_duration_seconds=duration, service_account=None,
            auth_kind="aws-assume-role", aws_role_arn=approval.role_arn,
            aws_region=approval.region, aws_session_duration_seconds=session,
            aws_profile_name=approval.profile_name,
            includes=(), variables={}, environment_names=frozenset(),
            leaf_names=frozenset({name}),
        )

    def _load_composite(
        self, name: str, data: dict[str, Any], stack: tuple[str, ...]
    ) -> Bundle:
        includes = self._string_list(data, "includes", nonempty=True)
        if len(includes) != len(set(includes)):
            raise BundleError("duplicate included bundle")
        members = [
            self._load(included_name, stack=(*stack, name))
            for included_name in includes
        ]
        auth_kinds = {member.auth_kind for member in members}
        if len(auth_kinds) != 1:
            raise BundleError("composite has incompatible authentication kinds")
        if auth_kinds != {"onepassword"}:
            raise BundleError("AWS assume-role bundles cannot be composite")

        accounts = {member.service_account.account for member in members if member.service_account}
        if len(accounts) != 1:
            raise BundleError("composite has incompatible service-account domains")
        common_vaults = set(members[0].service_account.vaults)
        for member in members[1:]:
            common_vaults.intersection_update(member.service_account.vaults)
        if not common_vaults:
            raise BundleError("composite has incompatible service-account vault constraints")

        environment_names: set[str] = set()
        leaf_names: set[str] = set()
        variables: dict[str, str] = {}
        for member in members:
            overlap = leaf_names.intersection(member.leaf_names)
            if overlap:
                raise BundleError(
                    f"duplicate included bundle: {sorted(overlap)[0]}"
                )
            leaf_names.update(member.leaf_names)
            self._claim_names(environment_names, member.environment_names, context=name)
            variables.update(member.variables)

        return Bundle(
            name=name,
            kind="composite",
            schema_version=1,
            description=data["description"],
            providers=tuple(
                sorted({provider for member in members for provider in member.providers})
            ),
            capabilities=tuple(
                sorted(
                    {
                        capability
                        for member in members
                        for capability in member.capabilities
                    }
                )
            ),
            risk=max(
                (member.risk for member in members), key=RISK_ORDER.__getitem__
            ),
            env_files=tuple(
                env_file for member in members for env_file in member.env_files
            ),
            injected_files=tuple(
                injected
                for member in members
                for injected in member.injected_files
            ),
            clear_variables=tuple(
                sorted(
                    {
                        variable
                        for member in members
                        for variable in member.clear_variables
                    }
                )
            ),
            identity_probes=tuple(
                sorted(
                    {
                        probe
                        for member in members
                        for probe in member.identity_probes
                    }
                )
            ),
            interactive=all(member.interactive for member in members),
            max_duration_seconds=min(
                member.max_duration_seconds for member in members
            ),
            service_account=ServiceAccountConstraint(
                account=accounts.pop(), vaults=tuple(sorted(common_vaults))
            ),
            auth_kind="onepassword",
            aws_role_arn=None,
            aws_region=None,
            aws_session_duration_seconds=None,
            aws_profile_name=None,
            includes=includes,
            variables=variables,
            environment_names=frozenset(environment_names),
            leaf_names=frozenset(leaf_names),
        )

    def _service_account(self, value: object) -> ServiceAccountConstraint:
        if not isinstance(value, dict):
            raise BundleError("service_account must be a table")
        self._check_exact_fields(value, SERVICE_ACCOUNT_FIELDS, "service_account")
        account = value["account"]
        if not isinstance(account, str) or not DOMAIN_PATTERN.fullmatch(account):
            raise BundleError("service_account.account is not a supported domain")
        vaults = self._string_list(value, "vaults", nonempty=True)
        if any(not LABEL_PATTERN.fullmatch(vault) for vault in vaults):
            raise BundleError("service_account vault name is invalid")
        return ServiceAccountConstraint(account=account, vaults=tuple(sorted(vaults)))

    def _injected_files(self, value: object) -> tuple[InjectedFile, ...]:
        if not isinstance(value, list):
            raise BundleError("injected_files must be an array of tables")
        injected_files: list[InjectedFile] = []
        for item in value:
            if not isinstance(item, dict):
                raise BundleError("injected_files must contain tables")
            self._check_exact_fields(item, INJECTED_FILE_FIELDS, "injected_files")
            template = item["template"]
            target_env = item["target_env"]
            if not isinstance(template, str) or not isinstance(target_env, str):
                raise BundleError("injected file fields must be strings")
            self._require_variable(target_env)
            with self._open_file(template, kind="template"):
                pass
            injected_files.append(
                InjectedFile(self._relative_path(template, kind="template"), target_env)
            )
        return tuple(injected_files)

    def _read_env_file(self, relative: str) -> dict[str, str]:
        raw = self._read_bytes(relative, kind="env-file")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BundleError("env-file is not valid UTF-8") from error
        if "\r" in text or any(
            (ord(character) < 0x20 and character != "\n")
            or ord(character) == 0x7F
            for character in text
        ):
            raise BundleError("invalid env-file: control characters are forbidden")

        variables: dict[str, str] = {}
        for line_number, line in enumerate(text.split("\n"), 1):
            if not line or line.startswith("#"):
                continue
            match = DOTENV_LINE_PATTERN.fullmatch(line)
            if match is None:
                raise BundleError(f"invalid env-file syntax on line {line_number}")
            variable = match.group("variable")
            reference = match.group("reference")
            if OP_REFERENCE_PATTERN.fullmatch(reference) is None:
                raise BundleError(
                    f"invalid env-file op reference on line {line_number}"
                )
            if variable in variables:
                raise BundleError(f"duplicate env-file variable {variable}")
            variables[variable] = reference
        return variables

    @staticmethod
    def _claim_names(
        claimed: set[str], incoming: Any, *, context: str
    ) -> None:
        for variable in incoming:
            if (
                variable in RESERVED_BUNDLE_ENV_NAMES
                or variable.startswith(RESERVED_BUNDLE_ENV_PREFIXES)
            ):
                raise BundleError(f"reserved environment name in {context}: {variable}")
            if variable in claimed:
                raise BundleError(
                    f"environment name collision in {context}: {variable}"
                )
            claimed.add(variable)

    @staticmethod
    def _require_safe_string(data: dict[str, Any], field: str) -> None:
        value = data[field]
        if not isinstance(value, str) or not value:
            raise BundleError(f"{field} must be a non-empty string")
        if _has_control_characters(value):
            raise BundleError(f"{field} contains a control character")

    @staticmethod
    def _is_string_list(value: object, *, nonempty: bool = False) -> bool:
        return (
            isinstance(value, list)
            and (not nonempty or bool(value))
            and all(
                isinstance(item, str)
                and bool(item)
                and not _has_control_characters(item)
                for item in value
            )
        )

    def _string_list(
        self, data: dict[str, Any], field: str, *, nonempty: bool = False
    ) -> tuple[str, ...]:
        if field not in data:
            raise BundleError(f"missing field: {field}")
        value = data[field]
        if not self._is_string_list(value, nonempty=nonempty):
            qualifier = "non-empty " if nonempty else ""
            raise BundleError(f"{field} must be a {qualifier}string list")
        return tuple(value)

    def _supported_list(
        self,
        data: dict[str, Any],
        field: str,
        supported: frozenset[str],
        *,
        label: str,
    ) -> tuple[str, ...]:
        values = self._string_list(data, field, nonempty=True)
        if len(values) != len(set(values)) or any(value not in supported for value in values):
            raise BundleError(f"{label} list contains an unsupported or duplicate value")
        return tuple(sorted(values))

    def _variable_list(self, data: dict[str, Any], field: str) -> tuple[str, ...]:
        values = self._string_list(data, field)
        if len(values) != len(set(values)):
            raise BundleError(f"{field} contains a duplicate variable")
        for value in values:
            self._require_variable(value)
        return values

    @staticmethod
    def _require_variable(value: str) -> None:
        if not VARIABLE_PATTERN.fullmatch(value):
            raise BundleError(f"invalid environment variable name: {value!r}")

    @staticmethod
    def _check_exact_fields(
        data: dict[str, Any], expected: set[str], context: str
    ) -> None:
        unknown = set(data) - expected
        missing = expected - set(data)
        if unknown:
            raise BundleError(
                f"unknown field(s) in {context}: {', '.join(sorted(unknown))}"
            )
        if missing:
            raise BundleError(
                f"missing field(s) in {context}: {', '.join(sorted(missing))}"
            )
