from __future__ import annotations

from pathlib import Path
import hashlib
import os
import subprocess
import sys
import tempfile
import time
import unittest

import access_env


class PackagingTests(unittest.TestCase):
    def test_version_has_one_authoritative_source(self) -> None:
        self.assertFalse(hasattr(access_env, "__version__"))

    def test_installed_console_entry_point_smoke(self) -> None:
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            environment = Path(temporary) / "venv"
            subprocess.run(
                [sys.executable, "-m", "venv", "--system-site-packages", environment],
                check=True,
                capture_output=True,
                text=True,
            )
            install = subprocess.run(
                [
                    environment / "bin/pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-build-isolation",
                    "--no-deps",
                    project,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(install.returncode, 0, install.stderr)
            result = subprocess.run(
                [environment / "bin/access", "--help"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("list", result.stdout)
            self.assertIn("status", result.stdout)
            version = subprocess.run(
                [environment / "bin/access", "--version"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertEqual(version.stdout, "access 0.1.1\n")

    @unittest.skipUnless(sys.platform.startswith("linux"), "release installer requires Linux")
    def test_release_installer_uses_digest_and_safe_destdir(self) -> None:
        project = Path(__file__).parents[1]
        installer = project / "scripts/install-release.sh"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheel_dir = root / "wheel"
            wheel_dir.mkdir()
            build_command = [
                "/usr/bin/python3", "-m", "pip", "wheel", "--no-deps",
                "--no-build-isolation", "--wheel-dir", wheel_dir, project,
            ]
            build = subprocess.run(
                build_command,
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            wheel = wheel_dir / "access_env-0.1.1-py3-none-any.whl"
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            destdir = root / "dest"
            destdir.mkdir(mode=0o700)
            hostile_cwd = root / "hostile-cwd"
            hostile_cwd.mkdir()
            marker = root / "sitecustomize-ran"
            (hostile_cwd / "sitecustomize.py").write_text(
                f"from pathlib import Path; Path({str(marker)!r}).write_text('unsafe')\n"
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "DESTDIR": str(destdir),
                    "PYTHONPATH": str(hostile_cwd),
                    "PIP_CONFIG_FILE": str(hostile_cwd / "pip.conf"),
                    "PIP_INDEX_URL": "https://invalid.example/simple",
                }
            )

            bad = subprocess.run(
                [installer, wheel, "0.1.1", "0" * 64], cwd=hostile_cwd,
                env=environment, check=False, capture_output=True, text=True,
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertFalse((destdir / "opt/access-env/releases/0.1.1").exists())

            process = subprocess.Popen(
                [installer, wheel, "0.1.1", digest], cwd=hostile_cwd,
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            final_release = destdir / "opt/access-env/releases/0.1.1"
            incomplete_release_published = False
            while process.poll() is None:
                if final_release.exists():
                    entry_point = final_release / "bin/access"
                    incomplete_release_published = not (
                        entry_point.is_file()
                        and os.access(entry_point, os.X_OK)
                    )
                    break
                time.sleep(0.005)
            stdout, stderr = process.communicate(timeout=20)
            result = subprocess.CompletedProcess(
                process.args, process.returncode, stdout, stderr
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(
                incomplete_release_published,
                "installer exposed an incomplete final release",
            )
            self.assertFalse(marker.exists())
            release = destdir / "opt/access-env/releases/0.1.1"
            smoke = subprocess.run(
                [release / "bin/access", "--help"], check=False,
                capture_output=True, text=True,
            )
            self.assertEqual(smoke.returncode, 0, smoke.stderr)
            self.assertNotEqual(
                (release / "bin/access").read_bytes().splitlines()[0],
                b"#!/bin/sh",
                "short-path install unexpectedly used the long-path launcher",
            )
            self.assertEqual(
                os.readlink(destdir / "opt/access-env/current"),
                "/opt/access-env/releases/0.1.1",
            )
            self.assertEqual(
                os.readlink(destdir / "usr/local/bin/access"),
                "/opt/access-env/current/bin/access",
            )
            self.assertEqual(
                list((destdir / "opt/access-env/releases").glob(".install-*")),
                [],
            )

            rollback = subprocess.run(
                [installer, "--rollback", "0.1.1"], env=environment,
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(rollback.returncode, 0, rollback.stderr)

            release.chmod(0o775)
            rollback = subprocess.run(
                [installer, "--rollback", "0.1.1"], env=environment,
                check=False, capture_output=True, text=True,
            )
            self.assertNotEqual(rollback.returncode, 0)
            self.assertIn("unsafe rollback release", rollback.stderr)

    @unittest.skipUnless(sys.platform.startswith("linux"), "release installer requires Linux")
    def test_release_installer_rejects_symlinked_destination_ancestor(self) -> None:
        project = Path(__file__).parents[1]
        installer = project / "scripts/install-release.sh"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destdir = root / "dest"
            destdir.mkdir(mode=0o700)
            outside = root / "outside"
            outside.mkdir()
            (destdir / "opt").symlink_to(outside, target_is_directory=True)
            result = subprocess.run(
                [installer, root / "missing.whl", "0.1.0", "0" * 64],
                env={**os.environ, "DESTDIR": str(destdir)}, check=False,
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe symlink", result.stderr)

    @unittest.skipUnless(sys.platform.startswith("linux"), "release installer requires Linux")
    def test_release_installer_relocates_long_path_console_launcher(self) -> None:
        project = Path(__file__).parents[1]
        installer = project / "scripts/install-release.sh"
        with tempfile.TemporaryDirectory(dir="/dev/shm") as temporary:
            root = Path(temporary)
            wheel_dir = root / "wheel"
            wheel_dir.mkdir()
            build = subprocess.run(
                [
                    "/usr/bin/python3", "-m", "pip", "wheel", "--no-deps",
                    "--no-build-isolation", "--wheel-dir", wheel_dir, project,
                ],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            wheel = wheel_dir / "access_env-0.1.1-py3-none-any.whl"
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            destdir = root / ("long-destination-" + "x" * 120)
            destdir.mkdir(mode=0o700)
            environment = {**os.environ, "DESTDIR": str(destdir)}

            install = subprocess.run(
                [installer, wheel, "0.1.1", digest],
                env=environment, check=False, capture_output=True, text=True,
            )
            self.assertEqual(install.returncode, 0, install.stderr)
            release = destdir / "opt/access-env/releases/0.1.1"
            launcher = release / "bin/access"
            smoke = subprocess.run(
                [launcher, "--help"], check=False,
                capture_output=True, text=True,
            )
            self.assertEqual(
                smoke.returncode, 0,
                f"{smoke.stderr}\nlauncher={launcher.read_bytes()!r}",
            )
            self.assertNotIn(
                b".install-0.1.1-",
                launcher.read_bytes(),
                "launcher still references the deleted staging release",
            )
