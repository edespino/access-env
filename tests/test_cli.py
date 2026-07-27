from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest


def run_cli(
    *args: str, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy() if environment is None else environment.copy()
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    return subprocess.run(
        [sys.executable, "-m", "access_env.cli", *args],
        capture_output=True,
        check=False,
        env=env,
        text=True,
    )


class CliTests(unittest.TestCase):
    def make_registry(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "bundles").mkdir()
        (root / "env").mkdir()
        (root / "templates").mkdir()
        for directory in (root, root / "bundles", root / "env", root / "templates"):
            directory.chmod(0o700)
        (root / "env/github-dev.env").write_text(
            "GH_TOKEN=op://Development/Fake-Token/credential\n"
        )
        (root / "templates/provider.tpl").write_text(
            "token=op://Development/Fake-Config/credential\n"
        )
        (root / "bundles/github-dev.toml").write_text(
            """\
schema_version = 1
kind = "leaf"
auth_kind = "onepassword"
name = "github-dev"
description = "Fake GitHub development identity"
providers = ["github"]
capabilities = ["repository-read"]
risk = "development"
env_files = ["env/github-dev.env"]
clear_variables = []
identity_probe = "github-user"
interactive = false
max_duration_seconds = 900

[service_account]
account = "example.1password.com"
vaults = ["Development"]

[[injected_files]]
template = "templates/provider.tpl"
target_env = "PROVIDER_CONFIG"
"""
        )
        for file in (
            root / "env/github-dev.env",
            root / "templates/provider.tpl",
            root / "bundles/github-dev.toml",
        ):
            file.chmod(0o600)
        return temporary, root

    def test_help_exposes_bootstrap_commands(self) -> None:
        result = run_cli("--help")

        self.assertEqual(result.returncode, 0)
        self.assertIn("list", result.stdout)
        self.assertIn("status", result.stdout)
        self.assertIn("run", result.stdout)
        self.assertNotIn("use", result.stdout)
        self.assertNotIn("--op-executable", result.stdout)
        self.assertNotIn("--bootstrap-token-file", result.stdout)

    def test_run_requires_separator_and_propagates_exit_without_logging_arguments(self) -> None:
        from contextlib import redirect_stderr, redirect_stdout
        import io
        from unittest import mock
        from access_env import cli

        temporary, root = self.make_registry()
        self.addCleanup(temporary.cleanup)
        output = io.StringIO()
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(root)}, clear=True):
            with mock.patch("access_env.cli.run_bundle", return_value=19) as runner:
                with redirect_stdout(output), redirect_stderr(output):
                    result = cli.main(
                        ["--config-root", str(root), "run", "github-dev", "--",
                         sys.executable, "-c", "pass", "argument-canary"]
                    )
        self.assertEqual(result, 19)
        self.assertEqual(runner.call_args.kwargs["op_executable"], "/usr/bin/op")
        self.assertEqual(
            runner.call_args.kwargs["bootstrap_token_file"], root / "bootstrap-token"
        )
        self.assertNotIn("argument-canary", output.getvalue())

    def test_list_prints_only_non_secret_bundle_metadata(self) -> None:
        temporary, root = self.make_registry()
        self.addCleanup(temporary.cleanup)

        result = run_cli("--config-root", str(root), "list")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("github-dev", result.stdout)
        self.assertIn("repository-read", result.stdout)
        self.assertNotIn("op://", result.stdout)
        self.assertNotIn("GH_TOKEN", result.stdout)

    def test_status_validates_configuration_without_resolving_credentials(self) -> None:
        temporary, root = self.make_registry()
        self.addCleanup(temporary.cleanup)

        result = run_cli("--config-root", str(root), "status")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("configuration: ready", result.stdout)
        self.assertIn("bundles: 1 valid", result.stdout)
        self.assertIn("credential resolution: not implemented", result.stdout)
        self.assertNotIn(str(root), result.stdout)
        self.assertNotIn("op://", result.stdout)

    def test_status_prints_trusted_root_only_when_verbose(self) -> None:
        temporary, root = self.make_registry()
        self.addCleanup(temporary.cleanup)

        result = run_cli("--verbose", "--config-root", str(root), "status")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"trusted root: {root}", result.stdout)

    def test_errors_escape_terminal_control_characters(self) -> None:
        temporary, root = self.make_registry()
        self.addCleanup(temporary.cleanup)
        unsafe = root / "bundles" / "bad\u001b[2J.toml"
        unsafe.write_text("invalid")
        unsafe.chmod(0o600)

        result = run_cli("--config-root", str(root), "list")

        self.assertEqual(result.returncode, 2)
        self.assertNotIn("\u001b", result.stderr)
        self.assertIn(r"\x1b", result.stderr)

    def test_list_rejects_terminal_formatting_characters_in_metadata(self) -> None:
        temporary, root = self.make_registry()
        self.addCleanup(temporary.cleanup)
        manifest = root / "bundles/github-dev.toml"
        manifest.write_text(
            manifest.read_text().replace(
                "Fake GitHub development identity",
                "Fake\u202eGitHub development identity",
            )
        )

        result = run_cli("--config-root", str(root), "list")

        self.assertEqual(result.returncode, 2)
        self.assertNotIn("\u202e", result.stdout + result.stderr)

    def test_status_fails_for_invalid_configuration(self) -> None:
        temporary, root = self.make_registry()
        self.addCleanup(temporary.cleanup)
        (root / "bundles/github-dev.toml").write_text("schema_version = 99\n")

        result = run_cli("--config-root", str(root), "status")

        self.assertEqual(result.returncode, 2)
        self.assertIn("configuration error:", result.stderr)
