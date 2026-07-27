from __future__ import annotations

from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER_ACCOUNT_IDS = {"000000000000", "111122223333", "444455556666"}


class RepositoryBoundaryTests(unittest.TestCase):
    def test_all_tracked_public_content_is_sanitized(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, check=True,
            capture_output=True,
        ).stdout.split(b"\0")
        paths = [ROOT / item.decode("utf-8") for item in tracked if item]
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in paths
            if path.is_file() and b"\0" not in path.read_bytes()[:8192]
        )
        account_ids = set(re.findall(r"arn:aws:iam::(\d{12}):role/", text))
        self.assertLessEqual(account_ids, PLACEHOLDER_ACCOUNT_IDS)
        private_key_header = "-----BEGIN " + "PRIVATE KEY-----"
        self.assertNotIn(private_key_header, text)
        self.assertFalse(
            any(
                path.name in {"bootstrap-token", "credentials"}
                or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}
                for path in paths
            )
        )

    def test_gitignore_covers_sensitive_and_generated_state(self) -> None:
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
        required = (
            ".venv/",
            "dist/",
            "build/",
            "*.egg-info/",
            "__pycache__/",
            ".pytest_cache/",
            "bootstrap-token",
            "*.pem",
            "*.key",
            "bundles/",
            "env/",
            "templates/",
            "runtime/",
        )
        for pattern in required:
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, ignored)
        self.assertIn("!examples/", ignored)
        self.assertIn("!examples/env/github-dev.env", ignored)
        self.assertNotIn("!examples/**", ignored)
        for hostile in (
            "examples/private.key",
            "examples/env/production.env",
            "examples/bundles/production.toml",
            "examples/schema/unreviewed.toml",
            "examples/templates/unreviewed.tpl",
            "examples/templates/credential.pem",
            "examples/bundles/bootstrap-token",
        ):
            with self.subTest(hostile=hostile):
                result = subprocess.run(
                    ["git", "check-ignore", "--no-index", "-q", hostile],
                    cwd=ROOT, check=False,
                )
                self.assertEqual(result.returncode, 0)

    def test_examples_are_sanitized_and_real_policy_is_absent(self) -> None:
        self.assertFalse(list((ROOT / "policies/aws").glob("*.json")))
        examples = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "examples").rglob("*"))
            if path.is_file()
        )
        account_ids = set(re.findall(r"arn:aws:iam::(\d{12}):role/", examples))
        self.assertTrue(account_ids)
        self.assertLessEqual(account_ids, PLACEHOLDER_ACCOUNT_IDS)
        self.assertIsNone(
            re.search(r"(?i)(secret|token|password)\s*=\s*[\"'][^\"']+[\"']", examples)
        )

    def test_public_repository_has_license_and_private_reporting_path(self) -> None:
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)
        self.assertIn("license = {file = \"LICENSE\"}", project)
        self.assertIn("security/advisories/new", security)
        self.assertIn("Do not open a public issue", security)
