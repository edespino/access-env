from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import sys
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from access_env.bundles import BundleRegistry
from access_env.execution import (
    ExecutionError, _resolve_trusted_executable,
    _validate_trusted_executable, run_bundle,
)

from tests.test_bundles import leaf_manifest


FAKE_OP = """#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import subprocess
import sys

if len(sys.argv) < 5 or sys.argv[1] != "run" or sys.argv[2] != "--env-file" or sys.argv[4] != "--":
    raise SystemExit(97)
if "--no-masking" in sys.argv or os.environ.get("OP_RUN_NO_MASKING"):
    raise SystemExit(96)

child_env = os.environ.copy()
child_env["FAKE_OP_SAW_BOOTSTRAP"] = str(
    child_env.get("OP_SERVICE_ACCOUNT_TOKEN") == "bootstrap-canary"
)
for line in Path(sys.argv[3]).read_text().splitlines():
    if line:
        name, reference = line.split("=", 1)
        if not reference.startswith("op://"):
            raise SystemExit(95)
        child_env[name] = "resolved-canary-" + name.lower()

result = subprocess.run(sys.argv[5:], env=child_env, capture_output=True)
masked_out, masked_err = result.stdout, result.stderr
for value in [v for k, v in child_env.items() if k == "OP_SERVICE_ACCOUNT_TOKEN" or k.endswith("_TOKEN")]:
    masked_out = masked_out.replace(value.encode(), b"[MASKED]")
    masked_err = masked_err.replace(value.encode(), b"[MASKED]")
sys.stdout.buffer.write(masked_out)
sys.stderr.buffer.write(masked_err)
if result.returncode < 0:
    os.kill(os.getpid(), -result.returncode)
raise SystemExit(result.returncode)
"""

FAKE_SYSTEMD_RUN = """#!/usr/bin/env python3
import os,subprocess,sys
expected="unix:path="+os.environ.get("XDG_RUNTIME_DIR","")+"/bus"
if not os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("DBUS_SESSION_BUS_ADDRESS") != expected:
 raise SystemExit(88)
unit=next(a.split("=",1)[1] for a in sys.argv if a.startswith("--unit="))
command=sys.argv[sys.argv.index("--")+1:]
env=os.environ.copy();env["FAKE_SCOPE_UNIT"]=unit
raise SystemExit(subprocess.run(command,env=env).returncode)
"""

FAKE_SYSTEMCTL = """#!/usr/bin/env python3
import os,signal,sys
expected="unix:path="+os.environ.get("XDG_RUNTIME_DIR","")+"/bus"
if not os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("DBUS_SESSION_BUS_ADDRESS") != expected:
 raise SystemExit(89)
if "show-environment" in sys.argv: raise SystemExit(0)
if "kill" in sys.argv:
 unit=sys.argv[-1]; sig=signal.SIGKILL if any("KILL" in a for a in sys.argv) else signal.SIGTERM
 for entry in os.listdir("/proc"):
  if not entry.isdigit() or int(entry)==os.getpid(): continue
  try: data=open("/proc/"+entry+"/environ","rb").read()
  except OSError: continue
  if ("FAKE_SCOPE_UNIT="+unit).encode()+b"\\0" in data:
   try: os.kill(int(entry),sig)
   except ProcessLookupError: pass
raise SystemExit(0)
"""


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux process semantics")
class ExecutionTests(unittest.TestCase):
    def make_fixture(
        self, *, risk: str = "development", duration: int = 5
    ) -> tuple[tempfile.TemporaryDirectory[str], object, Path, Path, dict[str, str]]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        for relative in ("bundles", "env", "templates"):
            (root / relative).mkdir()
        for directory in (root, root / "bundles", root / "env", root / "templates"):
            directory.chmod(0o700)

        manifest = leaf_manifest(
            "dev",
            risk=risk,
            duration=duration,
            variable="ACCESS_TEST_TOKEN",
        )
        (root / "bundles/dev.toml").write_text(manifest)
        (root / "env/dev.env").write_text(
            "ACCESS_TEST_TOKEN=op://Development/Fake-Execution/credential\n"
        )
        (root / "templates/provider.tpl").write_text(
            "token=op://Development/Fake-Config/credential\n"
        )
        fake_op = root / "fake-op"
        fake_op.write_text(FAKE_OP)
        (root / "fake-systemd-run").write_text(FAKE_SYSTEMD_RUN)
        (root / "fake-systemctl").write_text(FAKE_SYSTEMCTL)
        bootstrap = root / "bootstrap-token"
        bootstrap.write_text("bootstrap-canary\n")
        for file in (
            root / "bundles/dev.toml",
            root / "env/dev.env",
            root / "templates/provider.tpl",
            fake_op,
            root / "fake-systemd-run",
            root / "fake-systemctl",
            bootstrap,
        ):
            file.chmod(0o600)
        fake_op.chmod(0o700)
        (root / "fake-systemd-run").chmod(0o700)
        (root / "fake-systemctl").chmod(0o700)

        bundle = BundleRegistry(root).load("dev")
        base_env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
            "TERM": "xterm-test",
            "XDG_RUNTIME_DIR": str(root),
        }
        return temporary, bundle, fake_op, bootstrap, base_env

    def capture_command(self, output: Path, *extra: str) -> list[str]:
        code = (
            "import json,os,sys;"
            "json.dump({'argv':sys.argv[1:],'env':dict(os.environ)},"
            "open(sys.argv[1],'w'))"
        )
        return [sys.executable, "-c", code, str(output), *extra]

    def test_preserves_exact_metacharacter_argv_without_shell(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "capture.json"
        arguments = ["space value", "$(not-run)", ";", "*", '"quoted"']

        result = run_bundle(
            bundle,
            self.capture_command(output, *arguments),
            op_executable=fake_op,
            bootstrap_token_file=bootstrap,
            inherited_env=env,
        )

        self.assertEqual(result, 0)
        captured = json.loads(output.read_text())
        self.assertEqual(captured["argv"][1:], arguments)

    def test_clears_ambient_provider_credentials_and_masking_override(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "capture.json"
        ambient = {
            "AWS_ACCESS_KEY_ID": "ambient-canary",
            "AWS_SECRET_ACCESS_KEY": "ambient-canary",
            "AWS_SESSION_TOKEN": "ambient-canary",
            "AWS_PROFILE": "ambient-canary",
            "GH_TOKEN": "ambient-canary",
            "GITHUB_TOKEN": "ambient-canary",
            "GOOGLE_APPLICATION_CREDENTIALS": "ambient-canary",
            "CLOUDSDK_AUTH_ACCESS_TOKEN": "ambient-canary",
            "AZURE_CLIENT_SECRET": "ambient-canary",
            "OMNISTRATE_API_KEY": "ambient-canary",
            "OP_RUN_NO_MASKING": "1",
        }
        env.update(ambient)

        result = run_bundle(
            bundle,
            self.capture_command(output),
            op_executable=fake_op,
            bootstrap_token_file=bootstrap,
            inherited_env=env,
        )

        self.assertEqual(result, 0)
        child_env = json.loads(output.read_text())["env"]
        for variable in ambient:
            self.assertNotIn(variable, child_env)
        self.assertEqual(
            child_env["ACCESS_TEST_TOKEN"], "resolved-canary-access_test_token"
        )

    def test_bootstrap_token_reaches_op_but_not_final_command(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "capture.json"

        result = run_bundle(
            bundle,
            self.capture_command(output),
            op_executable=fake_op,
            bootstrap_token_file=bootstrap,
            inherited_env=env,
        )

        self.assertEqual(result, 0)
        child_env = json.loads(output.read_text())["env"]
        self.assertEqual(child_env["FAKE_OP_SAW_BOOTSTRAP"], "True")
        self.assertNotIn("OP_SERVICE_ACCOUNT_TOKEN", child_env)
        self.assertNotIn("bootstrap-canary", output.read_text())

    def test_preserves_unrelated_environment(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "capture.json"

        result = run_bundle(
            bundle,
            self.capture_command(output),
            op_executable=fake_op,
            bootstrap_token_file=bootstrap,
            inherited_env=env,
        )

        self.assertEqual(result, 0)
        self.assertEqual(
            json.loads(output.read_text())["env"]["TERM"], "xterm-test"
        )

    def test_propagates_exit_code_and_signal(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)

        exit_code = run_bundle(
            bundle,
            [sys.executable, "-c", "raise SystemExit(23)"],
            op_executable=fake_op,
            bootstrap_token_file=bootstrap,
            inherited_env=env,
        )
        signal_code = run_bundle(
            bundle,
            [
                sys.executable,
                "-c",
                "import os,signal; os.kill(os.getpid(), signal.SIGTERM)",
            ],
            op_executable=fake_op,
            bootstrap_token_file=bootstrap,
            inherited_env=env,
        )

        self.assertEqual(exit_code, 23)
        self.assertEqual(signal_code, -signal.SIGTERM)

    def test_enforces_timeout_and_kills_process_group(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture(duration=1)
        self.addCleanup(temporary.cleanup)
        pid_file = Path(temporary.name) / "child.pid"
        code = (
            "import pathlib,subprocess,sys,time;"
            "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
            "pathlib.Path(sys.argv[1]).write_text(str(child.pid));"
            "time.sleep(30)"
        )

        started = time.monotonic()
        with self.assertRaisesRegex(ExecutionError, "timed out"):
            run_bundle(
                bundle,
                [sys.executable, "-c", code, str(pid_file)],
                op_executable=fake_op,
                bootstrap_token_file=bootstrap,
                inherited_env=env,
            )

        self.assertLess(time.monotonic() - started, 4)
        child_pid = int(pid_file.read_text())
        self.assertTrue(self._eventually_dead(child_pid))

    def test_cleans_background_child_after_command_exit(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        pid_file = Path(temporary.name) / "background.pid"
        code = (
            "import pathlib,subprocess,sys;"
            "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
            "pathlib.Path(sys.argv[1]).write_text(str(child.pid))"
        )

        result = run_bundle(
            bundle,
            [sys.executable, "-c", code, str(pid_file)],
            op_executable=fake_op,
            bootstrap_token_file=bootstrap,
            inherited_env=env,
        )

        self.assertEqual(result, 0)
        self.assertTrue(self._eventually_dead(int(pid_file.read_text())))

    def test_rejects_publish_and_administration_bundles(self) -> None:
        for risk in ("production", "publish", "administration"):
            temporary, bundle, fake_op, bootstrap, env = self.make_fixture(risk=risk)
            with self.subTest(risk=risk):
                with self.assertRaisesRegex(ExecutionError, "not approved"):
                    run_bundle(
                        bundle,
                        [sys.executable, "-c", "pass"],
                        op_executable=fake_op,
                        bootstrap_token_file=bootstrap,
                        inherited_env=env,
                    )
            temporary.cleanup()

    def test_allows_build_bundle(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture(risk="build")
        self.addCleanup(temporary.cleanup)

        result = run_bundle(
            bundle,
            [sys.executable, "-c", "pass"],
            op_executable=fake_op,
            bootstrap_token_file=bootstrap,
            inherited_env=env,
        )

        self.assertEqual(result, 0)

    def test_isolated_absolute_launcher_ignores_shadow_package(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        shadow = Path(temporary.name) / "shadow/access_env"
        shadow.mkdir(parents=True)
        marker = Path(temporary.name) / "hijacked"
        (shadow / "__init__.py").write_text("")
        (shadow / "launcher.py").write_text(
            f"from pathlib import Path; Path({str(marker)!r}).write_text('yes')"
        )
        env["PYTHONPATH"] = str(shadow.parent)

        result = run_bundle(
            bundle,
            [sys.executable, "-c", "pass"],
            op_executable=fake_op,
            bootstrap_token_file=bootstrap,
            inherited_env=env,
        )

        self.assertEqual(result, 0)
        self.assertFalse(marker.exists())

    def test_minimal_allowlist_and_private_provider_state(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "capture.json"
        env.update(
            {
                "GH_ENTERPRISE_TOKEN": "alternate-canary",
                "GOOGLE_OAUTH_ACCESS_TOKEN": "alternate-canary",
                "ARM_CLIENT_SECRET": "alternate-canary",
                "PYTHONPATH": "/malicious",
                "PYTHONHOME": "/malicious",
                "HOME": "/ambient-home",
                "RANDOM_UNSAFE": "drop-me",
            }
        )

        result = run_bundle(
            bundle,
            self.capture_command(output),
            op_executable=fake_op,
            bootstrap_token_file=bootstrap,
            inherited_env=env,
            xdg_runtime_dir=Path(temporary.name),
        )

        self.assertEqual(result, 0)
        child = json.loads(output.read_text())["env"]
        for name in (
            "GH_ENTERPRISE_TOKEN",
            "GOOGLE_OAUTH_ACCESS_TOKEN",
            "ARM_CLIENT_SECRET",
            "PYTHONPATH",
            "PYTHONHOME",
            "RANDOM_UNSAFE",
        ):
            self.assertNotIn(name, child)
        self.assertTrue(child["HOME"].startswith(str(Path(temporary.name) / "access/")))
        for name in (
            "AWS_CONFIG_FILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "GH_CONFIG_DIR",
            "CLOUDSDK_CONFIG",
            "AZURE_CONFIG_DIR",
            "OMNISTRATE_CONFIG_DIR",
            "PYTHONPYCACHEPREFIX",
        ):
            self.assertTrue(child[name].startswith(child["HOME"] + "/"))

    def test_fake_op_masks_resolved_canary_output(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        helper = (
            "from pathlib import Path;import sys;"
            "from access_env.bundles import BundleRegistry;"
            "from access_env.execution import run_bundle;"
            "b=BundleRegistry(Path(sys.argv[1])).load('dev');"
            "raise SystemExit(run_bundle(b,[sys.executable,'-c',"
            "'import os;print(os.environ[\\\"ACCESS_TEST_TOKEN\\\"])'],"
            "op_executable=Path(sys.argv[2]),bootstrap_token_file=Path(sys.argv[3]),"
            "inherited_env={'PATH':__import__('os').environ.get('PATH',''),"
            "'XDG_RUNTIME_DIR':sys.argv[1]}))"
        )
        result = subprocess.run(
            [sys.executable, "-c", helper, temporary.name, fake_op, bootstrap],
            env={"PYTHONPATH": str(Path(__file__).parents[1] / "src"),
                 "PATH": env["PATH"]},
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[MASKED]", result.stdout)
        self.assertNotIn("resolved-canary", result.stdout + result.stderr)

    def test_systemd_scope_kills_setsid_descendant(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        pid_file = Path(temporary.name) / "setsid.pid"
        code = (
            "import pathlib,subprocess,sys;"
            "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
            "start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
            "pathlib.Path(sys.argv[1]).write_text(str(p.pid))"
        )
        result = run_bundle(
            bundle, [sys.executable, "-c", code, str(pid_file)],
            op_executable=fake_op, bootstrap_token_file=bootstrap,
            inherited_env=env, _systemd_run=Path(temporary.name)/"fake-systemd-run",
            _systemctl=Path(temporary.name)/"fake-systemctl",
        )
        self.assertEqual(result, 0)
        self.assertTrue(self._eventually_dead(int(pid_file.read_text())))

    def test_systemd_gets_validated_host_bus_but_final_command_gets_private_runtime(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "final-bus.json"
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={temporary.name}/bus"

        result = run_bundle(
            bundle, self.capture_command(output),
            op_executable=fake_op, bootstrap_token_file=bootstrap,
            inherited_env=env,
            _systemd_run=Path(temporary.name)/"fake-systemd-run",
            _systemctl=Path(temporary.name)/"fake-systemctl",
        )

        self.assertEqual(result, 0)
        final = json.loads(output.read_text())["env"]
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", final)
        self.assertNotIn("ACCESS_PRIVATE_RUNTIME", final)
        self.assertNotIn("NOTIFY_SOCKET", final)
        self.assertNotEqual(final["XDG_RUNTIME_DIR"], temporary.name)
        self.assertTrue(final["XDG_RUNTIME_DIR"].startswith(temporary.name + "/access/"))

    def test_rejects_arbitrary_user_bus_address(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        env["DBUS_SESSION_BUS_ADDRESS"] = "tcp:host=attacker.invalid"
        with self.assertRaisesRegex(ExecutionError, "DBUS_SESSION_BUS_ADDRESS"):
            run_bundle(
                bundle, [sys.executable, "-c", "pass"],
                op_executable=fake_op, bootstrap_token_file=bootstrap,
                inherited_env=env,
                _systemd_run=Path(temporary.name)/"fake-systemd-run",
                _systemctl=Path(temporary.name)/"fake-systemctl",
            )

    def test_wrapper_sigterm_returns_143_promptly_when_child_ignores_it(self) -> None:
        temporary, _bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        helper = (
            "from pathlib import Path;import sys;"
            "from access_env.bundles import BundleRegistry;"
            "from access_env.execution import run_bundle;"
            "r=Path(sys.argv[1]);b=BundleRegistry(r).load('dev');"
            "code='import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)';"
            "raise SystemExit(run_bundle(b,[sys.executable,'-c',code],"
            "op_executable=Path(sys.argv[2]),bootstrap_token_file=Path(sys.argv[3]),"
            "inherited_env={'PATH':__import__('os').environ.get('PATH',''),"
            "'XDG_RUNTIME_DIR':sys.argv[1]},_systemd_run=r/'fake-systemd-run',"
            "_systemctl=r/'fake-systemctl'))"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", helper, temporary.name, fake_op, bootstrap],
            env={"PYTHONPATH": str(Path(__file__).parents[1]/"src"), "PATH": env["PATH"]},
        )
        time.sleep(0.3)
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        result = process.wait(timeout=3)
        self.assertEqual(result, 143)
        self.assertLess(time.monotonic() - started, 2)

    def test_rejects_symlinked_or_user_owned_production_executable(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        executable = Path(temporary.name) / "op"
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o700)
        _validate_trusted_executable(executable, expected_uid=os.geteuid())
        with self.assertRaisesRegex(ExecutionError, "ownership"):
            _validate_trusted_executable(executable, expected_uid=os.geteuid() + 1)
        link = Path(temporary.name) / "op-link"
        link.symlink_to(executable)
        with self.assertRaisesRegex(ExecutionError, "non-symlink"):
            _validate_trusted_executable(link)

    def test_private_environment_filesystem_failure_is_execution_error_and_cleans_up(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        with mock.patch(
            "access_env.execution.sanitize_environment",
            side_effect=OSError("simulated private-home failure"),
        ):
            with self.assertRaisesRegex(ExecutionError, "private runtime"):
                run_bundle(
                    bundle, [sys.executable, "-c", "pass"],
                    op_executable=fake_op, bootstrap_token_file=bootstrap,
                    inherited_env=env,
                )
        self.assertEqual(list((Path(temporary.name) / "access").glob("invocation-*")), [])

    def test_reference_file_failure_is_execution_error_and_cleans_up(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        with mock.patch(
            "access_env.execution._write_reference_file",
            side_effect=OSError("simulated reference-file failure"),
        ):
            with self.assertRaisesRegex(ExecutionError, "reference file"):
                run_bundle(
                    bundle, [sys.executable, "-c", "pass"],
                    op_executable=fake_op, bootstrap_token_file=bootstrap,
                    inherited_env=env,
                )
        self.assertEqual(list((Path(temporary.name) / "access").glob("invocation-*")), [])

    def test_fails_closed_when_systemd_manager_is_unavailable(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ExecutionError, "containment is unavailable"):
            run_bundle(
                bundle, [sys.executable, "-c", "pass"],
                op_executable=fake_op, bootstrap_token_file=bootstrap,
                inherited_env=env,
                _systemd_run=Path(temporary.name) / "fake-systemd-run",
                _systemctl=Path("/usr/bin/false"),
            )

    def test_validates_package_symlink_chain_and_rejects_malicious_links(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        prefix = root / "approved"
        version = prefix / "2.0/dist"
        version.mkdir(parents=True)
        for directory in (root, prefix, prefix/"2.0", version):
            directory.chmod(0o755)
        target = version / "aws"
        target.write_text("#!/bin/sh\n")
        target.chmod(0o755)
        current = prefix / "current"
        current.symlink_to(prefix/"2.0", target_is_directory=True)
        entry = root / "aws"
        entry.symlink_to(current/"dist/aws")

        resolved = _resolve_trusted_executable(
            entry, approved_prefix=prefix, expected_uid=os.geteuid()
        )
        self.assertEqual(resolved, target)

        outside = root / "outside"
        outside.write_text("#!/bin/sh\n")
        outside.chmod(0o755)
        entry.unlink()
        entry.symlink_to(outside)
        with self.assertRaisesRegex(ExecutionError, "approved prefix"):
            _resolve_trusted_executable(
                entry, approved_prefix=prefix, expected_uid=os.geteuid()
            )
        entry.unlink()
        entry.symlink_to(current/"dist/aws")
        version.chmod(0o775)
        with self.assertRaisesRegex(ExecutionError, "writable"):
            _resolve_trusted_executable(
                entry, approved_prefix=prefix, expected_uid=os.geteuid()
            )

    def test_stalled_systemctl_is_bounded_and_fails_closed(self) -> None:
        temporary, bundle, fake_op, bootstrap, env = self.make_fixture()
        self.addCleanup(temporary.cleanup)
        stalled = Path(temporary.name) / "stalled-systemctl"
        stalled.write_text("#!/bin/sh\nsleep 30\n")
        stalled.chmod(0o700)
        started = time.monotonic()
        with self.assertRaisesRegex(ExecutionError, "containment is unavailable"):
            run_bundle(
                bundle, [sys.executable, "-c", "pass"],
                op_executable=fake_op, bootstrap_token_file=bootstrap,
                inherited_env=env,
                _systemd_run=Path(temporary.name)/"fake-systemd-run",
                _systemctl=stalled,
            )
        self.assertLess(time.monotonic() - started, 2)

    @staticmethod
    def _eventually_dead(pid: int) -> bool:
        for _ in range(40):
            try:
                status = Path(f"/proc/{pid}/stat").read_text().split()[2]
            except FileNotFoundError:
                return True
            if status == "Z":
                return True
            time.sleep(0.05)
        return False
