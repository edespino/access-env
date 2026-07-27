from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest

from access_env.bundles import BundleError, BundleRegistry


def leaf_manifest(
    name: str,
    *,
    provider: str = "github",
    capability: str = "repository-read",
    risk: str = "development",
    account: str = "example.1password.com",
    vaults: str = '"Development"',
    interactive: str = "false",
    duration: int = 900,
    variable: str | None = None,
    clear: str | None = None,
    target: str | None = None,
    probe: str = "github-user",
    include_auth_kind: bool = True,
) -> str:
    variable = variable or f"{name.upper().replace('-', '_')}_TOKEN"
    clear_line = f'clear_variables = ["{clear}"]' if clear else "clear_variables = []"
    injection = (
        f'\n[[injected_files]]\ntemplate = "templates/provider.tpl"\n'
        f'target_env = "{target}"\n'
        if target
        else "injected_files = []\n"
    )
    auth_line = 'auth_kind = "onepassword"\n' if include_auth_kind else ""
    return f"""\
schema_version = 1
kind = "leaf"
{auth_line}\
name = "{name}"
description = "Fake development identity"
providers = ["{provider}"]
capabilities = ["{capability}"]
risk = "{risk}"
env_files = ["env/{name}.env"]
{clear_line}
identity_probe = "{probe}"
interactive = {interactive}
max_duration_seconds = {duration}
{injection}

[service_account]
account = "{account}"
vaults = [{vaults}]
"""


def composite_manifest(name: str, includes: list[str], extra: str = "") -> str:
    members = ", ".join(f'"{member}"' for member in includes)
    return f"""\
schema_version = 1
kind = "composite"
name = "{name}"
description = "Derived composite identity"
includes = [{members}]
{extra}"""


class BundleRegistryTests(unittest.TestCase):
    def make_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "bundles").mkdir()
        (root / "env").mkdir()
        (root / "templates").mkdir()
        root.chmod(0o700)
        (root / "bundles").chmod(0o700)
        (root / "env").chmod(0o700)
        (root / "templates").chmod(0o700)
        (root / "templates/provider.tpl").write_text(
            "token=op://Development/Fake-Config/credential\n"
        )
        (root / "templates/provider.tpl").chmod(0o600)
        return temporary, root

    def write_leaf(self, root: Path, name: str, **kwargs: object) -> None:
        variable = kwargs.get("variable") or f"{name.upper().replace('-', '_')}_TOKEN"
        (root / "bundles" / f"{name}.toml").write_text(
            leaf_manifest(name, **kwargs)  # type: ignore[arg-type]
        )
        (root / "env" / f"{name}.env").write_text(
            f"{variable}=op://Development/Fake-{name}/credential\n"
        )
        (root / "bundles" / f"{name}.toml").chmod(0o600)
        (root / "env" / f"{name}.env").chmod(0o600)

    def write_composite(self, root: Path, name: str, includes: list[str], extra: str = "") -> None:
        (root / "bundles" / f"{name}.toml").write_text(
            composite_manifest(name, includes, extra)
        )
        (root / "bundles" / f"{name}.toml").chmod(0o600)

    def test_composite_policy_is_derived_and_cannot_downgrade_publish_leaf(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(
            root,
            "publish",
            provider="aws",
            capability="artifact-publish",
            risk="publish",
            duration=300,
            probe="aws-caller",
        )
        self.write_leaf(root, "dev", duration=900)
        self.write_composite(root, "combined", ["dev", "publish"])

        bundle = BundleRegistry(root).load("combined")

        self.assertEqual(bundle.risk, "publish")
        self.assertEqual(bundle.max_duration_seconds, 300)
        self.assertFalse(bundle.interactive)
        self.assertEqual(bundle.providers, ("aws", "github"))
        self.assertEqual(bundle.capabilities, ("artifact-publish", "repository-read"))

    def test_composite_rejects_parent_policy_fields(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "publish", risk="publish")
        self.write_composite(root, "combined", ["publish"], 'risk = "development"')

        with self.assertRaisesRegex(BundleError, "unknown field.*risk"):
            BundleRegistry(root).load("combined")

    def test_rejects_unsupported_schema_version(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "future")
        manifest = root / "bundles/future.toml"
        manifest.write_text(
            manifest.read_text().replace("schema_version = 1", "schema_version = 2")
        )

        with self.assertRaisesRegex(BundleError, "schema_version"):
            BundleRegistry(root).load("future")

    def test_rejects_reserved_bundle_environment_names_fail_closed(self) -> None:
        reserved_names = (
            "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
            "PATH", "HOME", "XDG_CONFIG_HOME", "PYTHONPATH", "PYTHONWARNINGS",
            "OP_SERVICE_ACCOUNT_TOKEN", "OP_RUN_NO_MASKING",
            "DBUS_SESSION_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS",
            "SYSTEMD_LOG_LEVEL", "NOTIFY_SOCKET", "INVOCATION_ID",
            "ACCESS_PRIVATE_RUNTIME", "AWS_CONFIG_FILE", "AWS_PROFILE",
            "AWS_REGION", "GH_CONFIG_DIR", "CLOUDSDK_CONFIG",
            "AZURE_CONFIG_DIR", "OMNISTRATE_CONFIG_DIR", "PIP_CACHE_DIR",
            "UV_CACHE_DIR", "TMPDIR",
        )
        for name in reserved_names:
            temporary, root = self.make_root()
            with self.subTest(name=name):
                self.write_leaf(root, "reserved", variable=name)
                with self.assertRaisesRegex(BundleError, "reserved environment name"):
                    BundleRegistry(root).load("reserved")
            temporary.cleanup()

        for field in ("clear", "target"):
            temporary, root = self.make_root()
            with self.subTest(field=field):
                self.write_leaf(root, "reserved", **{field: "ACCESS_PRIVATE_RUNTIME"})
                with self.assertRaisesRegex(BundleError, "reserved environment name"):
                    BundleRegistry(root).load("reserved")
            temporary.cleanup()

    def test_schema_v1_without_auth_kind_remains_onepassword(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "legacy")
        manifest = root / "bundles/legacy.toml"
        manifest.write_text(manifest.read_text().replace('auth_kind = "onepassword"\n', ""))

        bundle = BundleRegistry(root).load("legacy")

        self.assertEqual(bundle.auth_kind, "onepassword")
        self.assertIsNotNone(bundle.service_account)

    def test_composite_rejects_incompatible_service_account_domains(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "first", account="one.1password.com")
        self.write_leaf(root, "second", account="two.1password.com")
        self.write_composite(root, "combined", ["first", "second"])

        with self.assertRaisesRegex(BundleError, "service-account domains"):
            BundleRegistry(root).load("combined")

    def test_composite_intersects_vault_constraints(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "first", vaults='"Development", "Shared"')
        self.write_leaf(root, "second", vaults='"Shared", "Publish"')
        self.write_composite(root, "combined", ["first", "second"])

        bundle = BundleRegistry(root).load("combined")

        self.assertEqual(bundle.service_account.vaults, ("Shared",))

    def test_composite_rejects_disjoint_vault_constraints(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "first", vaults='"Development"')
        self.write_leaf(root, "second", vaults='"Publish"')
        self.write_composite(root, "combined", ["first", "second"])

        with self.assertRaisesRegex(BundleError, "vault constraints"):
            BundleRegistry(root).load("combined")

    def test_rejects_symlinked_root(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        link = root.parent / f"{root.name}-link"
        link.symlink_to(root, target_is_directory=True)
        self.addCleanup(link.unlink)

        with self.assertRaisesRegex(BundleError, "root.*symlink"):
            BundleRegistry(link)

    def test_rejects_wrong_owner_and_writable_root_directories_and_files(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "valid", target="PROVIDER_CONFIG")
        targets = [
            root,
            root / "bundles",
            root / "env",
            root / "templates",
            root / "bundles/valid.toml",
            root / "env/valid.env",
            root / "templates/provider.tpl",
        ]
        for target in targets:
            original = stat.S_IMODE(target.stat().st_mode)
            target.chmod(original | stat.S_IWGRP)
            with self.subTest(target=target):
                with self.assertRaisesRegex(BundleError, "group/world writable"):
                    BundleRegistry(root).load("valid")
            target.chmod(original)

        registry = BundleRegistry(root)
        registry._effective_uid = os.geteuid() + 1
        with self.assertRaisesRegex(BundleError, "effective user"):
            registry.load("valid")

    def test_rejects_path_names_and_escaping_symlinks(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(BundleError, "name"):
            BundleRegistry(root).load("../outside")

        outside = root.parent / "outside.toml"
        outside.write_text(leaf_manifest("escape"))
        os.symlink(outside, root / "bundles/escape.toml")
        with self.assertRaisesRegex(BundleError, "trusted root"):
            BundleRegistry(root).load("escape")

    def test_rejects_collisions_across_all_environment_namespaces(self) -> None:
        cases = (
            ({"variable": "SHARED"}, {"variable": "SHARED"}),
            ({"variable": "SHARED"}, {"clear": "SHARED"}),
            ({"variable": "SHARED"}, {"target": "SHARED"}),
            ({"clear": "SHARED"}, {"clear": "SHARED"}),
            ({"clear": "SHARED"}, {"target": "SHARED"}),
            ({"target": "SHARED"}, {"target": "SHARED"}),
        )
        for first_options, second_options in cases:
            temporary, root = self.make_root()
            with self.subTest(
                first_options=first_options, second_options=second_options
            ):
                self.write_leaf(root, "first", **first_options)
                self.write_leaf(root, "second", **second_options)
                self.write_composite(root, "combined", ["first", "second"])
                with self.assertRaisesRegex(BundleError, "environment name collision.*SHARED"):
                    BundleRegistry(root).load("combined")
            temporary.cleanup()

        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "self", variable="SHARED", target="SHARED")
        with self.assertRaisesRegex(BundleError, "environment name collision.*SHARED"):
            BundleRegistry(root).load("self")

    def test_rejects_duplicate_included_bundle(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "first")
        self.write_composite(root, "combined", ["first", "first"])
        with self.assertRaisesRegex(BundleError, "duplicate included bundle"):
            BundleRegistry(root).load("combined")

    def test_accepts_only_strict_dotenv_op_reference_grammar(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "valid")
        valid = root / "env/valid.env"
        valid.write_text(
            "# comment-only lines are allowed\n"
            "\n"
            "TOKEN=op://Development/Fake-Item/credential\n"
            "SECTION=op://Development/Fake-Item/section/credential\n"
        )
        bundle = BundleRegistry(root).load("valid")
        self.assertEqual(len(bundle.variables), 2)

    def test_rejects_invalid_dotenv_and_op_references(self) -> None:
        invalid_lines = (
            "TOKEN=plaintext",
            "TOKEN=op://",
            "TOKEN=op://vault/item",
            "TOKEN=op://vault/item/field/too/many",
            'TOKEN="op://vault/item/field"',
            "export TOKEN=op://vault/item/field",
            "TOKEN=op://vault/item/field # comment",
            " TOKEN=op://vault/item/field",
            "TOKEN =op://vault/item/field",
            "TOKEN= op://vault/item/field",
            "TOKEN=op://vault/item/field ",
            "TOKEN=op://vault/item/fi\teld",
            "TOKEN=op://vault/item/fi#eld",
        )
        for index, invalid_line in enumerate(invalid_lines):
            temporary, root = self.make_root()
            with self.subTest(line=invalid_line):
                self.write_leaf(root, "invalid")
                (root / "env/invalid.env").write_text(invalid_line + "\n")
                with self.assertRaisesRegex(BundleError, "invalid env-file"):
                    BundleRegistry(root).load("invalid")
            temporary.cleanup()

    def test_rejects_duplicate_dotenv_variables_and_invalid_utf8(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "invalid")
        (root / "env/invalid.env").write_text(
            "TOKEN=op://vault/item/field\nTOKEN=op://vault/item/field\n"
        )
        with self.assertRaisesRegex(BundleError, "duplicate.*TOKEN"):
            BundleRegistry(root).load("invalid")

        (root / "env/invalid.env").write_bytes(b"TOKEN=op://vault/item/field\n\xff")
        with self.assertRaisesRegex(BundleError, "UTF-8"):
            BundleRegistry(root).load("invalid")

    def test_rejects_unsupported_policy_and_unsafe_metadata(self) -> None:
        replacements = (
            ('providers = ["github"]', 'providers = ["unknown"]', "provider"),
            ('capabilities = ["repository-read"]', 'capabilities = ["BAD CAP"]', "capability"),
            ('risk = "development"', 'risk = "unknown"', "risk"),
            ('identity_probe = "github-user"', 'identity_probe = "shell-command"', "identity_probe"),
            ("max_duration_seconds = 900", "max_duration_seconds = 999999", "duration"),
            (
                'description = "Fake development identity"',
                'description = "bad\\u001b[2J"',
                "control character",
            ),
        )
        for old, new, expected in replacements:
            temporary, root = self.make_root()
            with self.subTest(replacement=new):
                content = leaf_manifest("invalid").replace(old, new)
                self.write_leaf(root, "invalid")
                (root / "bundles/invalid.toml").write_text(content)
                with self.assertRaisesRegex(BundleError, expected):
                    BundleRegistry(root).load("invalid")
            temporary.cleanup()

    def test_names_fails_closed_on_invalid_or_nonregular_entries(self) -> None:
        entries = ("bad name.toml", "README", "nested.toml")
        for entry in entries:
            temporary, root = self.make_root()
            with self.subTest(entry=entry):
                path = root / "bundles" / entry
                if entry == "nested.toml":
                    path.mkdir()
                else:
                    path.write_text("not a bundle")
                with self.assertRaisesRegex(BundleError, "invalid bundle entry"):
                    BundleRegistry(root).names()
            temporary.cleanup()

    def test_expected_filesystem_and_decode_errors_are_bundle_errors(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.write_leaf(root, "invalid")
        (root / "bundles/invalid.toml").write_bytes(b"\xff")
        with self.assertRaisesRegex(BundleError, "UTF-8"):
            BundleRegistry(root).load("invalid")

        (root / "bundles/invalid.toml").unlink()
        with self.assertRaisesRegex(BundleError, "manifest"):
            BundleRegistry(root).load("invalid")

    def test_rejects_repository_markers_in_nested_ancestors(self) -> None:
        for marker_kind in ("directory", "file"):
            temporary = tempfile.TemporaryDirectory()
            with self.subTest(marker_kind=marker_kind):
                ancestor = Path(temporary.name)
                marker = ancestor / ".git"
                if marker_kind == "directory":
                    marker.mkdir()
                else:
                    marker.write_text("gitdir: /trusted/worktrees/example\n")
                root = ancestor / "nested/registry"
                for relative in ("bundles", "env", "templates"):
                    (root / relative).mkdir(parents=True, exist_ok=True)
                for directory in (root, root / "bundles", root / "env", root / "templates"):
                    directory.chmod(0o700)
                self.write_leaf(root, "repo")
                with self.assertRaisesRegex(BundleError, "repository"):
                    BundleRegistry(root).load("repo")
            temporary.cleanup()

    def test_rejects_symlinked_registry_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            real_parent = base / "real"
            root = real_parent / "registry"
            for relative in ("bundles", "env", "templates"):
                (root / relative).mkdir(parents=True, exist_ok=True)
            for directory in (root, root / "bundles", root / "env", root / "templates"):
                directory.chmod(0o700)
            self.write_leaf(root, "linked")
            link = base / "link"
            link.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(BundleError, "ancestor.*symlink"):
                BundleRegistry(link / "registry")
