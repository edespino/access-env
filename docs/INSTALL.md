# Versioned installation, upgrade, and rollback

Requirements are Linux, Python 3.11 or newer, a functioning systemd user
manager (`systemd-run` and `systemctl`), and the 1Password CLI at `/usr/bin/op`
for onepassword bundles. AWS provider tools may use the validated
`/usr/local/bin/aws` chain for future probes. Trusted executables and their
root-owned, non-group/world-writable paths remain fail closed.

Build a wheel in a clean checkout without credentials. The build backend is
exactly pinned in `pyproject.toml`; normal isolated builds obtain that declared
tool rather than relying on an ambient virtual environment:

```console
python3 -m pip wheel --no-deps --wheel-dir dist .
sha256sum dist/access_env-*.whl
```

Transfer the wheel and its recorded SHA-256 digest through the host's approved
release channel. Pass that digest to the installer; it copies and hashes the
non-symlink artifact through one descriptor, validates wheel metadata/version,
and installs only that verified copy:

```console
sudo scripts/install-release.sh dist/access_env-0.1.0-py3-none-any.whl 0.1.0 EXPECTED_SHA256
```

The installer creates `/opt/access-env/releases/VERSION`, installs only the
wheel into its private virtual environment, atomically updates
`/opt/access-env/current`, and exposes `/usr/local/bin/access`. It does not copy
the source checkout, `.venv`, caches, build directories, registries, or secret
material.

Upgrade by installing a new, verified version. Roll back through the installer;
it rejects symlinked/writable release paths, validates root ownership and the
installed executable, and refuses unsafe `current`, `current.new`, or entry-point
link state before switching atomically:

```console
sudo scripts/install-release.sh --rollback PREVIOUS
```

Do not change `~/.config/access` during application upgrade. Review schema and
host-policy compatibility before switching `current`; retain the previous
release until status and offline validation succeed.
