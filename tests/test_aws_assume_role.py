from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import time
import tempfile
import unittest

from access_env.bundles import BundleError, BundleRegistry
from access_env.execution import run_bundle
from access_env.host_policy import AwsAssumeRolePolicy, HostPolicy
from tests.test_execution import FAKE_SYSTEMCTL, FAKE_SYSTEMD_RUN


ROLE = "arn:aws:iam::111122223333:role/example-build-role"
REGION = "us-east-1"
PROFILE = "access-example-build"
HOST_POLICY = HostPolicy(
    1,
    (AwsAssumeRolePolicy(ROLE, REGION, PROFILE, 3600, 14_400),),
)


def manifest(
    role: str = ROLE,
    region: str = REGION,
    session: int = 3600,
    maximum: int = 7200,
) -> str:
    return f"""schema_version = 1
kind = "leaf"
auth_kind = "aws-assume-role"
name = "aws-build"
description = "Fake AWS build role"
providers = ["aws"]
capabilities = ["artifact-build"]
risk = "build"
identity_probe = "aws-caller"
interactive = false
max_duration_seconds = {maximum}
role_arn = "{role}"
region = "{region}"
session_duration_seconds = {session}
"""


class AwsAssumeRoleTests(unittest.TestCase):
    def registry(self, root: Path) -> BundleRegistry:
        return BundleRegistry(root, _host_policy=HOST_POLICY)

    def root(self, content: str | None = None):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        for relative in ("bundles", "env", "templates"):
            (root / relative).mkdir()
        for path in (root, root / "bundles", root / "env", root / "templates"):
            path.chmod(0o700)
        bundle_file = root / "bundles/aws-build.toml"
        bundle_file.write_text(content or manifest())
        bundle_file.chmod(0o600)
        for name, body in (
            ("fake-systemd-run", FAKE_SYSTEMD_RUN),
            ("fake-systemctl", FAKE_SYSTEMCTL),
        ):
            executable = root / name
            executable.write_text(body)
            executable.chmod(0o700)
        return temporary, root

    def test_schema_allows_refreshable_multi_hour_build(self):
        temporary, root = self.root()
        self.addCleanup(temporary.cleanup)

        bundle = self.registry(root).load("aws-build")

        self.assertEqual(bundle.auth_kind, "aws-assume-role")
        self.assertEqual(bundle.max_duration_seconds, 7200)
        self.assertEqual(bundle.aws_session_duration_seconds, 3600)
        self.assertIsNone(bundle.service_account)

    def test_schema_rejects_wrong_role_region_session_and_excessive_runtime(self):
        cases = (
            manifest(role="not-an-arn"),
            manifest(role="arn:aws:iam::444455556666:role/example-build-role"),
            manifest(region="eu-west-1"),
            manifest(session=900),
            manifest(maximum=14401),
        )
        for content in cases:
            temporary, root = self.root(content)
            with self.subTest(content=content):
                with self.assertRaises(BundleError):
                    self.registry(root).load("aws-build")
            temporary.cleanup()

    def test_writes_exact_private_refreshable_profile_and_no_static_credentials(self):
        temporary, root = self.root()
        self.addCleanup(temporary.cleanup)
        capture = root / "capture.json"
        code = """\
import json, os, pathlib, stat, sys
config = pathlib.Path(os.environ["AWS_CONFIG_FILE"])
data = {
    "env": dict(os.environ),
    "config": config.read_text(),
    "mode": stat.S_IMODE(config.stat().st_mode),
    "credentials_exists": pathlib.Path(
        os.environ["AWS_SHARED_CREDENTIALS_FILE"]
    ).exists(),
    "config_path": str(config),
}
json.dump(data, open(sys.argv[1], "w"))
"""
        bundle = self.registry(root).load("aws-build")
        inherited = {
            "PATH": os.environ.get("PATH", ""),
            "XDG_RUNTIME_DIR": str(root),
            "AWS_PROFILE": "ambient",
            "AWS_CONFIG_FILE": "/ambient/config",
            "AWS_ACCESS_KEY_ID": "ambient-canary",
            "AWS_SECRET_ACCESS_KEY": "ambient-canary",
            "AWS_SESSION_TOKEN": "ambient-canary",
            "OP_SERVICE_ACCOUNT_TOKEN": "op-canary",
        }

        result = run_bundle(
            bundle,
            [sys.executable, "-c", code, str(capture)],
            op_executable=root / "must-not-run-op",
            bootstrap_token_file=root / "must-not-read-bootstrap",
            inherited_env=inherited,
            _systemd_run=root / "fake-systemd-run",
            _systemctl=root / "fake-systemctl",
        )

        self.assertEqual(result, 0)
        captured = json.loads(capture.read_text())
        environment = captured["env"]
        expected_lines = [
            f"[profile {PROFILE}]",
            f"role_arn = {ROLE}",
            "credential_source = Ec2InstanceMetadata",
            f"region = {REGION}",
            "duration_seconds = 3600",
        ]
        config_lines = captured["config"].splitlines()
        self.assertEqual(config_lines[:5], expected_lines)
        self.assertEqual(len(config_lines), 6)
        self.assertRegex(
            config_lines[5],
            r"^role_session_name = access-[0-9a-f]{20}$",
        )
        self.assertEqual(captured["mode"], 0o600)
        self.assertEqual(environment["AWS_PROFILE"], PROFILE)
        self.assertEqual(
            environment["AWS_DEFAULT_PROFILE"], PROFILE
        )
        self.assertEqual(environment["AWS_REGION"], REGION)
        self.assertEqual(environment["AWS_DEFAULT_REGION"], REGION)
        for variable in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "OP_SERVICE_ACCOUNT_TOKEN",
        ):
            self.assertNotIn(variable, environment)
        self.assertFalse(captured["credentials_exists"])
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", environment)
        self.assertTrue(
            captured["config_path"].startswith(str(root / "access/invocation-"))
        )
        self.assertEqual(
            environment["XDG_RUNTIME_DIR"],
            str(Path(captured["config_path"]).parents[2]),
        )
        self.assertFalse(Path(captured["config_path"]).exists())

    def test_profile_runtime_is_cleaned_after_setsid_descendant(self):
        temporary, root = self.root(manifest(maximum=5))
        self.addCleanup(temporary.cleanup)
        pid_file = root / "setsid.pid"
        runtime_file = root / "runtime.txt"
        code = (
            "import os,pathlib,subprocess,sys;"
            "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
            "start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
            "pathlib.Path(sys.argv[1]).write_text(str(p.pid));"
            "pathlib.Path(sys.argv[2]).write_text(os.environ['XDG_RUNTIME_DIR'])"
        )

        result = run_bundle(
            self.registry(root).load("aws-build"),
            [sys.executable, "-c", code, str(pid_file), str(runtime_file)],
            op_executable=root / "must-not-run-op",
            bootstrap_token_file=root / "must-not-read-bootstrap",
            inherited_env={
                "PATH": os.environ.get("PATH", ""),
                "XDG_RUNTIME_DIR": str(root),
            },
            _systemd_run=root / "fake-systemd-run",
            _systemctl=root / "fake-systemctl",
        )

        self.assertEqual(result, 0)
        child_pid = int(pid_file.read_text())
        for _ in range(40):
            try:
                state = Path(f"/proc/{child_pid}/stat").read_text().split()[2]
            except FileNotFoundError:
                break
            if state == "Z":
                break
            time.sleep(0.05)
        else:
            self.fail("detached descendant survived containment cleanup")
        self.assertFalse(Path(runtime_file.read_text()).exists())
