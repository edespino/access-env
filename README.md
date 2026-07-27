# access-env

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`access-env` lists and validates trusted access-bundle metadata and delegates
unresolved references through `op run`. For approved AWS role bundles it
writes a refreshable shared-config profile; provider tools—not `access`
itself—obtain credentials. It does not inject files. Tests use only fake
executables and canary values.

Requires Python 3.11 or newer:

```console
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/access --help
.venv/bin/access --version
```

The registry defaults to `~/.config/access`. Select another absolute,
user-controlled root explicitly:

```console
access --config-root /absolute/user-controlled/path list
access --config-root /absolute/user-controlled/path status
access --verbose --config-root /absolute/user-controlled/path status
access --config-root /absolute/user-controlled/path run development -- command arg
```

Normal status output deliberately omits the full trusted-root path.

## Trusted registry

The root must be outside a Git worktree, owned by the effective UID, a real
directory rather than a symlink, and not group/world writable. The same checks
apply to relevant directories, manifests, env files, and templates. Bundle
directory entries fail closed: every entry must be a regular, securely owned
`NAME.toml` file.

Files are opened with `O_NOFOLLOW` where the platform provides it and checked
with `fstat` after opening. Path containment and inode/device consistency are
also checked. A same-UID process can still race or replace user-owned
configuration; this slice follows the plan's explicit assumption that
same-UID agents are trusted peers. Stronger isolation requires a broker or
separate OS identities.

## Schema version 1

A leaf manifest has exactly these top-level fields:

```toml
schema_version = 1
kind = "leaf"
auth_kind = "onepassword"
name = "github-dev"
description = "Read-only GitHub identity"
providers = ["github"]
capabilities = ["repository-read"]
risk = "development"
env_files = ["env/github-dev.env"]
injected_files = []
clear_variables = []
identity_probe = "github-user"
interactive = false
max_duration_seconds = 900

[service_account]
account = "example.1password.com"
vaults = ["Development"]
```

`auth_kind = "onepassword"` preserves the unresolved `op://` workflow above.
The host also supports one non-secret AWS leaf:

```toml
schema_version = 1
kind = "leaf"
auth_kind = "aws-assume-role"
name = "example-ami-build"
description = "Example AMI builder"
providers = ["aws"]
capabilities = ["artifact-build"]
risk = "build"
identity_probe = "aws-caller"
interactive = false
max_duration_seconds = 7200
role_arn = "arn:aws:iam::111122223333:role/example-build-role"
region = "us-east-1"
session_duration_seconds = 3600
```

This mode has no env files, injected files, 1Password service-account metadata,
or bootstrap token. Role, region, profile name, session lifetime, and maximum
command duration must exactly match the root-controlled fixed policy at
`/etc/access-env/host-policy.toml`. There is no production policy-path option.
`access run` writes a private mode-0600 AWS shared-config profile inside the
invocation's mode-0700 runtime. The profile uses
`credential_source = Ec2InstanceMetadata`, a fixed 3600-second role session,
and a per-invocation session name. Final commands receive the fixed profile and
region selectors, an absent private shared-credentials path, and no static AWS
credential variables. AWS SDKs, the AWS CLI, and Packer can therefore refresh
the chained role session during a longer build. The command timeout remains
enforced and is capped at four hours for this auth kind.

The host user-bus selectors are supplied only to the containment tools. Final
commands receive the private invocation directory as `XDG_RUNTIME_DIR` and do
not receive `DBUS_SESSION_BUS_ADDRESS`.

`identity_probe` is metadata describing the fixed probe a future status slice
may execute. It is validated against the provider but is not automatically run
by `access run`; this slice therefore makes no claim that the assumed identity
was independently probed.

Supported providers are `aws`, `github`, `gcloud`, `azure`, and `omnistrate`.
Supported capabilities are `identity-read`, `repository-read`,
`repository-write`, `artifact-build`, `artifact-publish`, and
`administration`. Risk tiers, from lowest to highest, are `development`,
`build`, `production`, `publish`, and `administration`. Maximum duration is
86,400 seconds. Identity probes are fixed names tied to their provider:
`aws-caller`, `github-user`, `gcloud-account`, `azure-account`, and
`omnistrate-user`.

A composite manifest is intentionally policy-free:

```toml
schema_version = 1
kind = "composite"
name = "development"
description = "Derived development access"
includes = ["github-dev", "aws-build"]
```

Its providers and capabilities are unions; risk is the highest included tier;
duration is the shortest; interactivity requires every leaf; clear variables,
injected files, and probes are derived. Service-account domains must match and
allowed vaults are intersected. An empty intersection fails. Duplicate leaves
and any collision among dotenv variables, `target_env` values, clear
variables, or included bundles fail.

## Dotenv and `op://` subset

Env files are UTF-8 with LF line endings. The only accepted active line is:

```text
VARIABLE=op://vault/item/field
```

An optional section is supported:

```text
VARIABLE=op://vault/item/section/field
```

Variables use `[A-Za-z_][A-Za-z0-9_]*`. Every reference has exactly three or
four slash-separated components after `op://`; components use only ASCII
letters, digits, `.`, `_`, `~`, and `-`. Blank and comment-only lines beginning
with `#` are allowed. Plaintext, incomplete references, quotes, `export`,
inline comments, whitespace, control characters, duplicate variables, and
invalid UTF-8 are rejected.

## Mocked `access run`

The accepted form is exactly:

```console
access [OPTIONS] run BUNDLE -- COMMAND [ARG ...]
```

The command is executed as an argv list without a shell, `eval`, quoting
reconstruction, or argument logging. The wrapper creates a new session/process
group, applies the bundle lifetime to the complete `op`/command scope, forwards
interrupt and termination signals, and terminates remaining descendants after
normal exit, interruption, or timeout.

Before starting `op`, known AWS, GitHub, Google Cloud, Azure, Omnistrate, and
1Password credential variables are removed. Bundle `clear_variables` are also
removed; unrelated variables are preserved. `OP_RUN_NO_MASKING` is always
removed and there is no no-masking option.

The bootstrap token source is fixed at the private
`TRUSTED_ROOT/bootstrap-token` file. It must be owned by the effective UID, be a regular
non-symlink file, and have mode `0600` or stricter. The token is supplied only
to the `op` process. An internal launcher removes it before executing the final
command. Bundle references remain unresolved in a private temporary dotenv
file passed to:

```text
op run --env-file PRIVATE_FILE -- INTERNAL_LAUNCHER -- COMMAND ...
```

Only `development` and `build` risk tiers may run. `production`, `publish`, and
`administration` are denied until a separate approval mechanism exists.
Bundles requiring injected files are also denied because `op inject` is not
implemented.

Production execution uses only the validated, absolute `/usr/bin/op`; the CLI
has no executable or bootstrap-path override. Tests inject a purpose-built fake
binary through the internal Python API only and never invoke an installed
1Password CLI or use real credentials.

Every run requires a validated, non-symlink `XDG_RUNTIME_DIR` owned by the
effective UID with mode `0700`. Private `access/invocation-*` directories hold
an isolated HOME, caches, and AWS, GitHub, Google Cloud, Azure, Omnistrate, and
Python state. Inheritance uses a small locale/terminal/tool allowlist rather
than a credential denylist.

Production commands run in a uniquely named systemd user scope. The wrapper
fails closed when the user manager is unavailable and always sends
TERM/grace/KILL followed by unit stop/reset cleanup. This cgroup boundary
contains descendants even if they create a new POSIX session.

For the AWS leaf, `access` does not invoke AWS during credential setup and does
not acquire, parse, or hold temporary credentials. It writes only the private
shared-config role profile described above. Provider tools perform IMDS source
credential discovery and role refresh inside the contained final command.
Ambient AWS selectors and credentials cannot override the fixed profile.

The trusted `/usr/local/bin/aws` package symlink-chain validator remains
available for a future explicit metadata identity probe. Such a probe is not
performed by this slice: `identity_probe = "aws-caller"` is validated metadata,
not a claim of automatic verification.

All `systemctl` probes, kills, stops, and resets are bounded. Signal handlers
only record the signal and forward it to the wrapper process group; potentially
blocking cgroup cleanup occurs afterward in normal control flow with a
process-group fallback.

The systemd wrapper and systemctl helpers receive only the validated host
user-bus selectors needed to reach the user manager. `XDG_RUNTIME_DIR` must
already pass the ownership, non-symlink, and mode-0700 checks.
`DBUS_SESSION_BUS_ADDRESS`, when inherited, must equal
`unix:path=$XDG_RUNTIME_DIR/bus`; otherwise that standard address is derived.
Arbitrary transports and paths fail closed. The internal launcher removes the
bus address and other systemd control variables, then replaces
`XDG_RUNTIME_DIR` with the private per-invocation runtime before executing the
target command. Final commands therefore cannot use the host user-manager bus.

`examples/schema/aws-assume-role.toml` uses a deliberately fake account and is
illustrative only; it is not intended to pass the host's fixed-role policy or
be copied into the live bundle directory.

The source repository is code, tests, documentation, and deliberately fake
examples only. Actual bundles, dotenv files, templates, bootstrap material,
credentials, keys, runtime state, and `~/.config/access` remain outside Git.
See [Repository boundary](docs/REPOSITORY_BOUNDARY.md) and
[installation and upgrades](docs/INSTALL.md).

The `examples/` tree contains only deliberately fake `op://` references. Copy
the relevant registry example files outside this repository and set private
modes before testing:

```console
test ! -e "$HOME/.config/access" || { echo "access registry already exists" >&2; exit 1; }
umask 077
mkdir -p "$HOME/.config/access"
cp -R examples/bundles examples/env examples/templates "$HOME/.config/access/"
chmod 700 ~/.config/access ~/.config/access/{bundles,env,templates}
chmod 600 ~/.config/access/bundles/* ~/.config/access/env/* \
  ~/.config/access/templates/*
access status
```

Run tests with:

```console
python -m pytest
```

## License

Licensed under the [Apache License 2.0](LICENSE).
