from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from access_env import host_policy
from access_env.host_policy import HostPolicyError, load_host_policy


FAKE_POLICY = """schema_version = 1

[[aws_assume_roles]]
role_arn = "arn:aws:iam::111122223333:role/example-build-role"
region = "us-east-1"
profile_name = "access-example-build"
session_duration_seconds = 3600
max_command_duration_seconds = 14400
"""


class HostPolicyTests(unittest.TestCase):
    def test_schema_version_rejects_toml_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            policy = root / "host-policy.toml"
            policy.write_text(FAKE_POLICY.replace("schema_version = 1", "schema_version = true"))
            policy.chmod(0o600)
            with self.assertRaisesRegex(HostPolicyError, "schema version"):
                load_host_policy(_path=policy, _expected_uid=os.geteuid())

    def test_strict_policy_parsing_and_secure_file_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            policy = root / "host-policy.toml"
            policy.write_text(FAKE_POLICY)
            policy.chmod(0o600)

            loaded = load_host_policy(_path=policy, _expected_uid=os.geteuid())

            approved = loaded.aws_assume_roles[0]
            self.assertEqual(
                approved.role_arn,
                "arn:aws:iam::111122223333:role/example-build-role",
            )
            self.assertEqual(approved.profile_name, "access-example-build")

            policy.write_text(
                FAKE_POLICY.replace(
                    "\n[[aws_assume_roles]]",
                    "\nunknown_top_level = true\n\n[[aws_assume_roles]]",
                )
            )
            with self.assertRaises(HostPolicyError):
                load_host_policy(_path=policy, _expected_uid=os.geteuid())
            policy.write_text(FAKE_POLICY + "\nunknown_role_field = true\n")
            with self.assertRaises(HostPolicyError):
                load_host_policy(_path=policy, _expected_uid=os.geteuid())

    def test_default_fixed_path_is_used_and_missing_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            policy = root / "host-policy.toml"
            with mock.patch.object(host_policy, "HOST_POLICY_PATH", policy):
                with self.assertRaisesRegex(HostPolicyError, "unavailable"):
                    load_host_policy(_expected_uid=os.geteuid())
                policy.write_text(FAKE_POLICY)
                policy.chmod(0o600)
                loaded = load_host_policy(_expected_uid=os.geteuid())
            self.assertEqual(len(loaded.aws_assume_roles), 1)

    def test_rejects_wrong_owner_and_nonregular_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            policy = root / "host-policy.toml"
            policy.write_text(FAKE_POLICY)
            policy.chmod(0o600)
            with self.assertRaisesRegex(HostPolicyError, "trusted"):
                load_host_policy(
                    _path=policy, _expected_uid=os.geteuid() + 1
                )
            policy.unlink()
            policy.mkdir()
            with self.assertRaises(HostPolicyError):
                load_host_policy(_path=policy, _expected_uid=os.geteuid())

    def test_rejects_symlink_and_writable_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            target = root / "target.toml"
            target.write_text(FAKE_POLICY)
            target.chmod(0o600)
            link = root / "host-policy.toml"
            link.symlink_to(target)
            with self.assertRaises(HostPolicyError):
                load_host_policy(_path=link, _expected_uid=os.geteuid())
            link.unlink()
            target.chmod(0o620)
            with self.assertRaises(HostPolicyError):
                load_host_policy(_path=target, _expected_uid=os.geteuid())
