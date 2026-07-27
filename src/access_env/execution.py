from __future__ import annotations

import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
from types import FrameType
from typing import Mapping, Sequence

from .bundles import Bundle
from .runtime import RuntimeError as PrivateRuntimeError, invocation_runtime


TRUSTED_OP = Path("/usr/bin/op")
TRUSTED_SYSTEMD_RUN = Path("/usr/bin/systemd-run")
TRUSTED_SYSTEMCTL = Path("/usr/bin/systemctl")
TRUSTED_AWS = Path("/usr/local/bin/aws")
SAFE_INHERITED = frozenset(
    {"PATH", "LANG", "LANGUAGE", "TERM", "COLORTERM", "NO_COLOR", "TZ",
     "USER", "LOGNAME", "SHELL", "DISPLAY", "WAYLAND_DISPLAY", "EDITOR",
     "VISUAL", "PAGER"}
)
ALLOWED_RUN_RISKS = frozenset({"development", "build"})
TERMINATION_GRACE_SECONDS = 0.5
SYSTEMCTL_TIMEOUT_SECONDS = 0.5


class ExecutionError(RuntimeError):
    """A bundle cannot be executed safely."""


class _ReceivedSignal(BaseException):
    pass


def sanitize_environment(
    inherited: Mapping[str, str], clear_variables: Sequence[str], runtime: Path
) -> dict[str, str]:
    environment = {
        key: value for key, value in inherited.items()
        if key in SAFE_INHERITED or key.startswith("LC_")
    }
    for variable in clear_variables:
        environment.pop(variable, None)
    home = runtime / "home"
    paths = {
        "HOME": home, "XDG_CACHE_HOME": home / "cache",
        "XDG_CONFIG_HOME": home / "config", "XDG_DATA_HOME": home / "data",
        "XDG_STATE_HOME": home / "state", "TMPDIR": home / "tmp",
        "AWS_CONFIG_FILE": home / "aws/config",
        "AWS_SHARED_CREDENTIALS_FILE": home / "aws/credentials",
        "GH_CONFIG_DIR": home / "github", "CLOUDSDK_CONFIG": home / "gcloud",
        "AZURE_CONFIG_DIR": home / "azure",
        "OMNISTRATE_CONFIG_DIR": home / "omnistrate",
        "PYTHONPYCACHEPREFIX": home / "python/pycache",
        "PIP_CACHE_DIR": home / "python/pip", "UV_CACHE_DIR": home / "python/uv",
    }
    file_selectors = {"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"}
    for key, path in paths.items():
        target = path.parent if key in file_selectors else path
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
    environment.update({key: os.fspath(value) for key, value in paths.items()})
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _validated_user_bus_environment(
    runtime_root: Path, inherited: Mapping[str, str]
) -> dict[str, str]:
    expected = f"unix:path={runtime_root}/bus"
    supplied = inherited.get("DBUS_SESSION_BUS_ADDRESS")
    if supplied is not None and supplied != expected:
        raise ExecutionError(
            "DBUS_SESSION_BUS_ADDRESS does not match the validated user runtime"
        )
    return {
        "XDG_RUNTIME_DIR": os.fspath(runtime_root),
        "DBUS_SESSION_BUS_ADDRESS": expected,
    }


def _validate_trusted_executable(path: Path, *, expected_uid: int = 0) -> None:
    try:
        result = path.lstat()
    except OSError as error:
        raise ExecutionError("trusted executable is unavailable") from error
    if stat.S_ISLNK(result.st_mode) or not stat.S_ISREG(result.st_mode):
        raise ExecutionError("trusted executable must be a non-symlink regular file")
    if result.st_uid != expected_uid or result.st_mode & 0o022:
        raise ExecutionError("trusted executable has unsafe ownership or mode")


def _resolve_trusted_executable(
    path: Path, *, approved_prefix: Path, expected_uid: int = 0
) -> Path:
    path = path.absolute()
    prefix = approved_prefix.absolute()
    anchor = prefix.parent

    def validate_node(result: os.stat_result, label: str, directory: bool = False) -> None:
        if result.st_uid != expected_uid:
            raise ExecutionError(f"{label} has unsafe ownership")
        if not stat.S_ISLNK(result.st_mode) and result.st_mode & 0o022:
            raise ExecutionError(f"{label} is group/world writable")
        if directory and not (
            stat.S_ISDIR(result.st_mode) or stat.S_ISLNK(result.st_mode)
        ):
            raise ExecutionError(f"{label} is not a directory")

    current = path
    for depth in range(17):
        try:
            result = current.lstat()
        except OSError as error:
            raise ExecutionError("trusted executable chain is unavailable") from error
        validate_node(result, "trusted executable chain")
        parent = current.parent
        while parent.is_relative_to(anchor) and parent != anchor.parent:
            try:
                parent_result = parent.lstat()
            except OSError as error:
                raise ExecutionError("trusted executable parent is unavailable") from error
            validate_node(parent_result, "trusted executable parent", directory=True)
            if stat.S_ISLNK(parent_result.st_mode):
                try:
                    resolved_parent = parent.resolve(strict=True)
                except OSError as error:
                    raise ExecutionError("trusted executable parent link is invalid") from error
                if not resolved_parent.is_relative_to(prefix):
                    raise ExecutionError("trusted executable parent escapes approved prefix")
                resolved_cursor = resolved_parent
                while resolved_cursor.is_relative_to(prefix):
                    validate_node(
                        resolved_cursor.lstat(),
                        "trusted executable resolved parent",
                        directory=True,
                    )
                    if resolved_cursor == prefix:
                        break
                    resolved_cursor = resolved_cursor.parent
            if parent == anchor:
                break
            parent = parent.parent
        if stat.S_ISLNK(result.st_mode):
            try:
                target = Path(os.readlink(current))
            except OSError as error:
                raise ExecutionError("trusted executable link cannot be read") from error
            current = target if target.is_absolute() else current.parent / target
            current = Path(os.path.normpath(current))
            if not current.is_relative_to(prefix):
                raise ExecutionError("trusted executable link escapes approved prefix")
            continue
        if not stat.S_ISREG(result.st_mode) or not result.st_mode & 0o111:
            raise ExecutionError("trusted executable target is not executable")
        resolved_final = current.resolve(strict=True)
        if not resolved_final.is_relative_to(prefix):
            raise ExecutionError("trusted executable target escapes approved prefix")
        return resolved_final
    raise ExecutionError("trusted executable symlink chain is too deep")


def _read_bootstrap_token(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        path_stat = path.lstat()
        if stat.S_ISLNK(path_stat.st_mode):
            raise ExecutionError("bootstrap token source must not be a symlink")
        descriptor = os.open(path, flags)
    except ExecutionError:
        raise
    except OSError as error:
        raise ExecutionError("bootstrap token source is unavailable") from error
    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise ExecutionError("bootstrap token source must be a regular file")
        if opened_stat.st_uid != os.geteuid():
            raise ExecutionError("bootstrap token source must be owned by the effective user")
        if opened_stat.st_mode & 0o077:
            raise ExecutionError("bootstrap token source must have mode 0600 or stricter")
        if (
            opened_stat.st_dev != path_stat.st_dev
            or opened_stat.st_ino != path_stat.st_ino
        ):
            raise ExecutionError("bootstrap token source changed while being opened")
        chunks: list[bytes] = []
        remaining = 65_537
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError as error:
        raise ExecutionError("bootstrap token source cannot be read") from error
    finally:
        os.close(descriptor)
    if len(raw) > 65_536:
        raise ExecutionError("bootstrap token source is unexpectedly large")
    try:
        token = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ExecutionError("bootstrap token source is not valid UTF-8") from error
    if token.endswith("\n"):
        token = token[:-1]
    if not token or "\n" in token or "\r" in token:
        raise ExecutionError("bootstrap token source must contain exactly one value")
    return token


def _write_reference_file(directory: Path, bundle: Bundle) -> Path:
    path = directory / "bundle.env"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        content = "".join(
            f"{variable}={reference}\n"
            for variable, reference in sorted(bundle.variables.items())
        ).encode("utf-8")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
    finally:
        os.close(descriptor)
    return path


def _write_aws_role_profile(environment: Mapping[str, str], bundle: Bundle, session_name: str) -> None:
    path = Path(environment["AWS_CONFIG_FILE"])
    content = (
        f"[profile {bundle.aws_profile_name}]\n"
        f"role_arn = {bundle.aws_role_arn}\n"
        "credential_source = Ec2InstanceMetadata\n"
        f"region = {bundle.aws_region}\n"
        f"duration_seconds = {bundle.aws_session_duration_seconds}\n"
        f"role_session_name = {session_name}\n"
    ).encode("ascii")
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            view = memoryview(content)
            while view:
                view = view[os.write(descriptor, view):]
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ExecutionError("private AWS role profile could not be created") from error


def _signal_group(process_group: int, signum: int) -> None:
    try:
        os.killpg(process_group, signum)
    except ProcessLookupError:
        pass


def _terminate_group(process: subprocess.Popen[bytes], process_group: int) -> None:
    _signal_group(process_group, signal.SIGTERM)
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        _signal_group(process_group, signal.SIGKILL)
        process.wait()
    _signal_group(process_group, signal.SIGKILL)


def _kill_scope(
    systemctl: Path, unit: str, signal_name: str, bus_environment: Mapping[str, str]
) -> None:
    _run_bounded_tool(
        [systemctl, "--user", "kill", "--kill-whom=all",
         f"--signal={signal_name}", unit],
        environment=bus_environment,
    )


def _run_bounded_tool(
    argv: Sequence[str | Path], *, environment: Mapping[str, str] | None = None
) -> int:
    try:
        process = subprocess.Popen(
            [os.fspath(item) for item in argv],
            env=None if environment is None else dict(environment),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return 126
    try:
        return process.wait(timeout=SYSTEMCTL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _terminate_group(process, process.pid)
        return 124


def _bounded_systemctl(
    systemctl: Path, *arguments: str, environment: Mapping[str, str]
) -> int:
    return _run_bounded_tool(
        [systemctl, "--user", *arguments], environment=environment
    )


def _cleanup_containment(
    process: subprocess.Popen[bytes],
    process_group: int,
    systemctl: Path | None,
    unit: str,
    bus_environment: Mapping[str, str],
) -> None:
    if systemctl is None:
        _terminate_group(process, process_group)
        return
    _kill_scope(systemctl, unit, "TERM", bus_environment)
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    _kill_scope(systemctl, unit, "KILL", bus_environment)
    _bounded_systemctl(systemctl, "stop", unit, environment=bus_environment)
    _bounded_systemctl(
        systemctl, "reset-failed", unit, environment=bus_environment
    )
    if process.poll() is None:
        _terminate_group(process, process_group)


def run_bundle(
    bundle: Bundle,
    command: Sequence[str],
    *,
    op_executable: str | Path,
    bootstrap_token_file: str | Path,
    inherited_env: Mapping[str, str],
    xdg_runtime_dir: Path | None = None,
    _systemd_run: Path | None = None,
    _systemctl: Path | None = None,
) -> int:
    if not command or not command[0]:
        raise ExecutionError("a non-empty command is required")
    if bundle.risk not in ALLOWED_RUN_RISKS:
        raise ExecutionError(f"{bundle.risk} bundles are not approved for access run")
    if bundle.injected_files:
        raise ExecutionError("injected files are not supported by access run yet")

    runtime_root = xdg_runtime_dir
    if runtime_root is None:
        configured = inherited_env.get("XDG_RUNTIME_DIR")
        if not configured:
            raise ExecutionError("validated XDG_RUNTIME_DIR is required")
        runtime_root = Path(configured)
    try:
      runtime_context = invocation_runtime(runtime_root)
      with runtime_context as temporary_path:
        try:
            environment = sanitize_environment(
                inherited_env, bundle.clear_variables, temporary_path
            )
        except OSError as error:
            raise ExecutionError("private runtime environment could not be created") from error
        environment["ACCESS_PRIVATE_RUNTIME"] = os.fspath(temporary_path)
        use_systemd = (
            Path(op_executable) == TRUSTED_OP
            or bundle.auth_kind == "aws-assume-role"
            or _systemd_run is not None
        )
        bus_environment = (
            _validated_user_bus_environment(runtime_root, inherited_env)
            if use_systemd
            else {}
        )
        launcher = Path(__file__).with_name("launcher.py").absolute()
        launcher_argv = [sys.executable, "-I", os.fspath(launcher), "--", *command]
        if bundle.auth_kind == "aws-assume-role":
            environment["AWS_EC2_METADATA_DISABLED"] = "false"
            session_name = f"access-{temporary_path.name[-20:]}"
            _write_aws_role_profile(environment, bundle, session_name)
            environment["AWS_PROFILE"] = bundle.aws_profile_name
            environment["AWS_DEFAULT_PROFILE"] = bundle.aws_profile_name
            environment["AWS_REGION"] = bundle.aws_region
            environment["AWS_DEFAULT_REGION"] = bundle.aws_region
            command_argv = launcher_argv
        else:
            environment["OP_SERVICE_ACCOUNT_TOKEN"] = _read_bootstrap_token(Path(bootstrap_token_file))
            try:
                reference_file = _write_reference_file(temporary_path, bundle)
            except OSError as error:
                raise ExecutionError("private reference file could not be created") from error
            command_argv = [
                os.fspath(op_executable), "run", "--env-file",
                os.fspath(reference_file), "--", *launcher_argv,
            ]
        unit = f"access-{temporary_path.name.removeprefix('invocation-')}.scope"
        if use_systemd:
            systemd_run = _systemd_run or TRUSTED_SYSTEMD_RUN
            systemctl = _systemctl or TRUSTED_SYSTEMCTL
            if _systemd_run is None:
                executables = [systemd_run, systemctl, launcher]
                if bundle.auth_kind != "aws-assume-role":
                    executables.insert(0, TRUSTED_OP)
                for executable in executables:
                    _validate_trusted_executable(executable)
            if _bounded_systemctl(
                systemctl, "show-environment", environment=bus_environment
            ):
                raise ExecutionError("required systemd user containment is unavailable")
            argv = [
                os.fspath(systemd_run), "--user", "--scope", "--quiet",
                f"--unit={unit}", "--", *command_argv,
            ]
        else:
            systemctl = None
            argv = command_argv
        process_environment = environment.copy()
        if use_systemd:
            process_environment.update(bus_environment)
        try:
            process = subprocess.Popen(
                argv,
                env=process_environment,
                start_new_session=True,
            )
        except OSError as error:
            raise ExecutionError("configured op executable could not be started") from error

        process_group = process.pid
        previous_handlers: dict[int, signal.Handlers] = {}
        received_signal: list[int] = []

        def forward_signal(
            signum: int, _frame: FrameType | None
        ) -> None:
            if not received_signal:
                received_signal.append(signum)
            _signal_group(process_group, signum)
            raise _ReceivedSignal

        handlers_installed = False
        try:
            if (
                hasattr(signal, "SIGINT")
                and hasattr(signal, "SIGTERM")
                and _in_main_thread()
            ):
                for signum in (signal.SIGINT, signal.SIGTERM):
                    previous_handlers[signum] = signal.getsignal(signum)
                    signal.signal(signum, forward_signal)
                handlers_installed = True
            try:
                return_code = process.wait(timeout=bundle.max_duration_seconds)
            except subprocess.TimeoutExpired as error:
                _cleanup_containment(
                    process, process_group, systemctl, unit, bus_environment
                )
                raise ExecutionError(
                    f"bundle execution timed out after {bundle.max_duration_seconds} seconds"
                ) from error
            except KeyboardInterrupt:
                _signal_group(process_group, signal.SIGINT)
                _terminate_group(process, process_group)
                raise
            except _ReceivedSignal:
                _cleanup_containment(
                    process, process_group, systemctl, unit, bus_environment
                )
                return 128 + received_signal[0]
            _cleanup_containment(
                process, process_group, systemctl, unit, bus_environment
            )
            if received_signal:
                return 128 + received_signal[0]
            return return_code
        finally:
            if process.poll() is None:
                _cleanup_containment(
                    process, process_group, systemctl, unit, bus_environment
                )
            if handlers_installed:
                for signum, handler in previous_handlers.items():
                    signal.signal(signum, handler)
    except PrivateRuntimeError as error:
        raise ExecutionError(str(error)) from error


def _in_main_thread() -> bool:
    import threading

    return threading.current_thread() is threading.main_thread()
