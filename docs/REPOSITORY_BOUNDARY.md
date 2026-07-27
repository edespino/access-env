# Repository boundary

This portable source repository contains application source, tests, CI,
installation tools, documentation, and deliberately fake examples. It must
never contain a live registry, bundle, dotenv file, injected template,
bootstrap token, credential, private key, provider state, runtime directory,
or environment IAM policy.

Production bundle content remains under the user's `~/.config/access` and is
created during first-host bootstrap outside Git. Host approval policy remains
at the fixed root-controlled `/etc/access-env/host-policy.toml`. Start from
`examples/host-policy.toml`, replace fake identifiers on the host, install it
as root-owned mode 0600 beneath a root-owned, non-writable `/etc/access-env`,
and separately create the user registry with the ownership and modes described
in the README.

The IAM JSON under `policies/aws/` is deliberately incomplete and sanitized.
It is a review aid, not a generic deployable policy. Environment-specific IAM
policy must be maintained outside this repository and reviewed independently.

Linux with a working systemd user manager is the supported containment
environment. This repository makes no macOS or Windows containment claim.
