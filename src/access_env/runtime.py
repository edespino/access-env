from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import stat
from typing import Iterator
import uuid


class RuntimeError(ValueError):
    """The private runtime directory is unavailable or unsafe."""


def _validate(path: Path, uid: int) -> None:
    try:
        result = path.lstat()
    except OSError as error:
        raise RuntimeError("XDG_RUNTIME_DIR is unavailable") from error
    if stat.S_ISLNK(result.st_mode):
        raise RuntimeError("XDG_RUNTIME_DIR must not be a symlink")
    if not stat.S_ISDIR(result.st_mode):
        raise RuntimeError("XDG_RUNTIME_DIR must be a directory")
    if result.st_uid != uid:
        raise RuntimeError("XDG_RUNTIME_DIR must be owned by the effective user")
    if stat.S_IMODE(result.st_mode) != 0o700:
        raise RuntimeError("XDG_RUNTIME_DIR must have mode 0700")


@contextmanager
def invocation_runtime(
    root: Path, *, effective_uid: int | None = None
) -> Iterator[Path]:
    uid = os.geteuid() if effective_uid is None else effective_uid
    _validate(root, uid)
    access_root = root / "access"
    try:
        access_root.mkdir(mode=0o700, exist_ok=True)
    except OSError as error:
        raise RuntimeError("access runtime directory cannot be created") from error
    _validate(access_root, uid)
    invocation = access_root / f"invocation-{uuid.uuid4().hex}"
    try:
        invocation.mkdir(mode=0o700)
    except OSError as error:
        raise RuntimeError("invocation runtime directory cannot be created") from error
    try:
        yield invocation
    finally:
        shutil.rmtree(invocation, ignore_errors=True)
