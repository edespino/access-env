#!/bin/sh
set -eu

# This script may run as root from an untrusted working directory. Use only
# fixed system executables and discard interpreter/package-manager influence.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
IFS=$(/usr/bin/printf ' 	\n_')
IFS=${IFS%_}
export PATH HOME IFS
unset CDPATH ENV BASH_ENV PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT \
  PYTHONWARNINGS PYTHONUSERBASE PIP_CONFIG_FILE PIP_INDEX_URL PIP_EXTRA_INDEX_URL \
  PIP_TRUSTED_HOST PIP_REQUIRE_VIRTUALENV PIP_TARGET PIP_PREFIX PIP_USER \
  PIP_CACHE_DIR UV_CACHE_DIR VIRTUAL_ENV || true
umask 022

usage() {
  echo "usage: install-release.sh WHEEL VERSION SHA256" >&2
  echo "       install-release.sh --rollback VERSION" >&2
  exit 2
}

[ "$#" -ge 1 ] || usage
original_cwd=$(/bin/pwd -P)
uid=$(/usr/bin/id -u)
prefix=${DESTDIR:-}
case "$prefix" in
  '') [ "$uid" -eq 0 ] || { echo "live installer must run as root" >&2; exit 1; } ;;
  /*) ;;
  *) echo "DESTDIR must be an absolute path" >&2; exit 2 ;;
esac

opt_root="${prefix}/opt/access-env"
releases_root="$opt_root/releases"
bin_root="${prefix}/usr/local/bin"
current="$opt_root/current"
current_new="$opt_root/current.new"
access_link="$bin_root/access"

# Python is isolated (-I -S), receives no inherited environment, and runs from
# a root-controlled directory rather than the caller's checkout.
cd /

validate_paths() {
  /usr/bin/env -i PATH="$PATH" HOME="$HOME" /usr/bin/python3 -I -S - "$uid" "$prefix" "$opt_root" "$releases_root" "$bin_root" <<'PY'
import os, pathlib, stat, sys
uid = int(sys.argv[1])
paths = [pathlib.Path(p) for p in sys.argv[2:] if p]

def trusted(path, *, directory=True):
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise SystemExit(f"unsafe symlink in destination path: {path}")
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(st.st_mode) or st.st_uid != uid or st.st_mode & 0o022:
        raise SystemExit(f"unsafe ownership, mode, or type: {path}")

for path in paths:
    cursor = path
    existing = []
    while not cursor.exists():
        if cursor.is_symlink():
            raise SystemExit(f"unsafe dangling symlink: {cursor}")
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    while True:
        existing.append(cursor)
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    # Only enforce ownership/mode from DESTDIR down (or /opt and /usr for live
    # installs); system ancestors are fixed OS trust anchors.
    floor = pathlib.Path(sys.argv[2]) if sys.argv[2] else pathlib.Path("/")
    for node in existing:
        if node == pathlib.Path("/"):
            continue
        if stat.S_ISLNK(node.lstat().st_mode):
            raise SystemExit(f"unsafe symlink in destination ancestor: {node}")
        if (sys.argv[2] and (node == floor or floor in node.parents)) or not sys.argv[2]:
            trusted(node)
PY
}

validate_release() {
  release_path=$1
  /usr/bin/env -i PATH="$PATH" HOME="$HOME" /usr/bin/python3 -I -S - "$uid" "$release_path" <<'PY'
import pathlib, stat, sys
uid = int(sys.argv[1]); release = pathlib.Path(sys.argv[2])
for path, kind in ((release, "directory"), (release / "bin", "directory"),
                   (release / "bin/access", "file")):
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or st.st_uid != uid or st.st_mode & 0o022:
        raise SystemExit(f"unsafe rollback release path: {path}")
    if kind == "directory" and not stat.S_ISDIR(st.st_mode):
        raise SystemExit(f"rollback path is not a directory: {path}")
    if kind == "file" and (not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111):
        raise SystemExit(f"rollback entry point is not a trusted executable: {path}")
PY
}

validate_version() {
  /usr/bin/env -i PATH="$PATH" HOME="$HOME" /usr/bin/python3 -I -S - "$1" <<'PY'
import re, sys
if re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3}", sys.argv[1]) is None:
    raise SystemExit("invalid release version")
PY
}

validate_link_state() {
  if [ -e "$current_new" ] || [ -L "$current_new" ]; then
    echo "unsafe existing current.new path" >&2
    exit 1
  fi
  if [ -e "$current" ] || [ -L "$current" ]; then
    [ -L "$current" ] || { echo "current must be a symlink" >&2; exit 1; }
    old_target=$(/usr/bin/readlink "$current")
    case "$old_target" in
      /opt/access-env/releases/*) ;;
      *) echo "current symlink has an unsafe target" >&2; exit 1 ;;
    esac
    old_version=${old_target#/opt/access-env/releases/}
    validate_version "$old_version"
    validate_release "$releases_root/$old_version"
  fi
  if [ -e "$access_link" ] || [ -L "$access_link" ]; then
    [ -L "$access_link" ] || { echo "access entry point must be a symlink" >&2; exit 1; }
    [ "$(/usr/bin/readlink "$access_link")" = "/opt/access-env/current/bin/access" ] || {
      echo "access entry point has an unsafe target" >&2
      exit 1
    }
  fi
}

switch_current() {
  version=$1
  validate_release "$releases_root/$version"
  validate_link_state
  /bin/ln -s "/opt/access-env/releases/$version" "$current_new"
  /bin/mv -Tf "$current_new" "$current"
  if [ ! -L "$access_link" ]; then
    /bin/ln -s "/opt/access-env/current/bin/access" "$access_link"
  fi
}

validate_paths
/usr/bin/install -d -m 0755 "${prefix}/opt" "${prefix}/usr" \
  "${prefix}/usr/local" "$opt_root" "$releases_root" "$bin_root"
validate_paths

if [ "$1" = "--rollback" ]; then
  [ "$#" -eq 2 ] || usage
  version=$2
  validate_version "$version"
  switch_current "$version"
  exit 0
fi

[ "$#" -eq 3 ] || usage
wheel=$1
version=$2
expected_digest=$3
validate_version "$version"
case "$wheel" in
  /*) ;;
  *) wheel="$original_cwd/$wheel" ;;
esac
final_release="$releases_root/$version"
staging_release="$releases_root/.install-${version}-$$"
if [ -e "$final_release" ] || [ -L "$final_release" ]; then
  echo "release already exists" >&2
  exit 1
fi
if [ -e "$staging_release" ] || [ -L "$staging_release" ]; then
  echo "staging release already exists" >&2
  exit 1
fi
/usr/bin/install -d -m 0700 "$staging_release"
cleanup_release=1
trap 'if [ "${cleanup_release:-0}" -eq 1 ]; then /bin/rm -rf -- "$staging_release"; fi' EXIT HUP INT TERM
artifact="$staging_release/access_env-${version}-py3-none-any.whl"

# Copy and hash through one O_NOFOLLOW descriptor, then validate the copied
# wheel's filename, ZIP paths, distribution metadata, and exact version.
/usr/bin/env -i PATH="$PATH" HOME="$HOME" /usr/bin/python3 -I -S - \
  "$wheel" "$artifact" "$expected_digest" "$version" <<'PY'
import hashlib, os, pathlib, re, stat, sys, zipfile
source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
expected = sys.argv[3].lower()
version = sys.argv[4]
if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
    raise SystemExit("invalid SHA-256 digest")
if source.name != f"access_env-{version}-py3-none-any.whl":
    raise SystemExit("wheel filename does not match release version")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
src = os.open(source, flags)
try:
    st = os.fstat(src)
    if not stat.S_ISREG(st.st_mode):
        raise SystemExit("wheel must be a regular non-symlink file")
    out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
    digest = hashlib.sha256()
    try:
        while chunk := os.read(src, 1024 * 1024):
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(out, view):]
        os.fsync(out)
    finally:
        os.close(out)
finally:
    os.close(src)
if digest.hexdigest() != expected:
    destination.unlink(missing_ok=True)
    raise SystemExit("wheel SHA-256 does not match")
try:
    with zipfile.ZipFile(destination) as archive:
        names = archive.namelist()
        if any(pathlib.PurePosixPath(n).is_absolute() or ".." in pathlib.PurePosixPath(n).parts for n in names):
            raise SystemExit("wheel contains an unsafe path")
        metadata_name = f"access_env-{version}.dist-info/METADATA"
        if names.count(metadata_name) != 1 or f"access_env-{version}.dist-info/RECORD" not in names:
            raise SystemExit("wheel metadata layout does not match release")
        metadata = archive.read(metadata_name).decode("utf-8")
        fields = dict(line.split(": ", 1) for line in metadata.splitlines() if ": " in line)
        if fields.get("Name") != "access-env" or fields.get("Version") != version:
            raise SystemExit("wheel metadata does not match release")
except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as error:
    destination.unlink(missing_ok=True)
    raise SystemExit("wheel is not a valid release artifact") from error
PY

/usr/bin/env -i PATH="$PATH" HOME="$HOME" PYTHONNOUSERSITE=1 \
  /usr/bin/python3 -I -m venv "$staging_release"
/usr/bin/env -i PATH="$PATH" HOME="$HOME" PYTHONNOUSERSITE=1 PIP_CONFIG_FILE=/dev/null \
  "$staging_release/bin/python" -I -m pip install --isolated --disable-pip-version-check \
  --no-index --no-deps --no-cache-dir "$artifact"
# Virtual-environment console scripts embed their absolute interpreter path.
# Rewrite only generated shebangs while the release is still private so the
# completed directory remains functional after its atomic rename.
/usr/bin/env -i PATH="$PATH" HOME="$HOME" /usr/bin/python3 -I -S - \
  "$staging_release" "$final_release" <<'PY'
import pathlib, stat, sys
staging = pathlib.Path(sys.argv[1])
final = pathlib.Path(sys.argv[2])
old = f"#!{staging}/bin/python".encode()
new = f"#!{final}/bin/python".encode()
for path in (staging / "bin").iterdir():
    result = path.lstat()
    if not stat.S_ISREG(result.st_mode):
        continue
    content = path.read_bytes()
    first, separator, remainder = content.partition(b"\n")
    if first.startswith(old):
        path.write_bytes(new + first[len(old):] + separator + remainder)
        path.chmod(stat.S_IMODE(result.st_mode))
PY
/bin/chmod 0755 "$staging_release"
validate_release "$staging_release"
/bin/mv -T "$staging_release" "$final_release"
staging_release="$final_release"
switch_current "$version"
cleanup_release=0
trap - EXIT HUP INT TERM
