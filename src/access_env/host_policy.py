"""Secure loader for the root-controlled, host-specific access policy."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import tomllib


HOST_POLICY_PATH = Path("/etc/access-env/host-policy.toml")
_TOP_LEVEL_FIELDS = {"schema_version", "aws_assume_roles"}
_ROLE_FIELDS = {
    "role_arn",
    "region",
    "profile_name",
    "session_duration_seconds",
    "max_command_duration_seconds",
}
_ROLE_ARN = re.compile(
    r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}\Z"
)
_REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-[1-9]\Z")
_PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


class HostPolicyError(ValueError):
    """The fixed host policy is absent, unsafe, or invalid."""


@dataclass(frozen=True)
class AwsAssumeRolePolicy:
    role_arn: str
    region: str
    profile_name: str
    session_duration_seconds: int
    max_command_duration_seconds: int


@dataclass(frozen=True)
class HostPolicy:
    schema_version: int
    aws_assume_roles: tuple[AwsAssumeRolePolicy, ...]

    def approved_role(self, role_arn: str, region: str) -> AwsAssumeRolePolicy:
        matches = [
            role
            for role in self.aws_assume_roles
            if role.role_arn == role_arn and role.region == region
        ]
        if len(matches) != 1:
            raise HostPolicyError("AWS role and region are not approved by host policy")
        return matches[0]


def _validate_directory(path: Path, expected_uid: int) -> None:
    try:
        result = path.lstat()
    except OSError as error:
        raise HostPolicyError("host policy directory is unavailable") from error
    if (
        stat.S_ISLNK(result.st_mode)
        or not stat.S_ISDIR(result.st_mode)
        or result.st_uid != expected_uid
        or result.st_mode & 0o022
    ):
        raise HostPolicyError("host policy directory is not trusted")


def load_host_policy(
    *, _path: Path | None = None, _expected_uid: int = 0
) -> HostPolicy:
    """Load the fixed production policy; alternate paths are test-only."""
    path = HOST_POLICY_PATH if _path is None else _path
    path = path.absolute()
    _validate_directory(path.parent, _expected_uid)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HostPolicyError("host policy is unavailable") from error
    try:
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != _expected_uid
            or opened.st_mode & 0o022
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise HostPolicyError("host policy file is not trusted")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = tomllib.load(stream)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise HostPolicyError("host policy cannot be decoded") from error
    finally:
        os.close(descriptor)
    if not isinstance(data, dict) or set(data) != _TOP_LEVEL_FIELDS:
        raise HostPolicyError("host policy has unknown or missing fields")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise HostPolicyError("unsupported host policy schema version")
    raw_roles = data["aws_assume_roles"]
    if not isinstance(raw_roles, list) or not raw_roles:
        raise HostPolicyError("host policy must approve at least one AWS role")
    roles: list[AwsAssumeRolePolicy] = []
    for raw in raw_roles:
        if not isinstance(raw, dict) or set(raw) != _ROLE_FIELDS:
            raise HostPolicyError("AWS role policy has unknown or missing fields")
        role_arn = raw["role_arn"]
        region = raw["region"]
        profile = raw["profile_name"]
        session = raw["session_duration_seconds"]
        maximum = raw["max_command_duration_seconds"]
        if (
            not isinstance(role_arn, str)
            or not _ROLE_ARN.fullmatch(role_arn)
            or not isinstance(region, str)
            or not _REGION.fullmatch(region)
            or not isinstance(profile, str)
            or not _PROFILE.fullmatch(profile)
            or type(session) is not int
            or session < 900
            or session > 43_200
            or type(maximum) is not int
            or maximum < 1
            or maximum > 86_400
        ):
            raise HostPolicyError("AWS role policy contains an invalid value")
        roles.append(
            AwsAssumeRolePolicy(role_arn, region, profile, session, maximum)
        )
    identities = {(role.role_arn, role.region) for role in roles}
    if len(identities) != len(roles):
        raise HostPolicyError("host policy contains duplicate AWS role approvals")
    return HostPolicy(1, tuple(roles))
