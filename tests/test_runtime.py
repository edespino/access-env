from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from access_env.runtime import RuntimeError, invocation_runtime


class RuntimeTests(unittest.TestCase):
    def test_rejects_symlink_wrong_mode_and_wrong_owner(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        link = root.parent / f"{root.name}-link"
        link.symlink_to(root, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            with invocation_runtime(link):
                pass

        root.chmod(0o770)
        with self.assertRaisesRegex(RuntimeError, "0700"):
            with invocation_runtime(root):
                pass
        root.chmod(0o700)

        with self.assertRaisesRegex(RuntimeError, "effective user"):
            with invocation_runtime(root, effective_uid=os.geteuid() + 1):
                pass

    def test_creates_private_access_and_invocation_directories(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        root.chmod(0o700)
        with invocation_runtime(root) as invocation:
            self.assertEqual(invocation.parent, root / "access")
            self.assertEqual(invocation.stat().st_mode & 0o777, 0o700)
            self.assertEqual(invocation.parent.stat().st_mode & 0o777, 0o700)
        self.assertFalse(invocation.exists())
