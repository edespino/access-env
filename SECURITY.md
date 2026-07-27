# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include credentials,
secret references, live bundle contents, tokens, keys, account identifiers, or
host configuration in a report.

Report vulnerabilities privately through GitHub Security Advisories:

https://github.com/edespino/access-env/security/advisories/new

Include the affected version, a minimal sanitized reproduction, the expected
security boundary, and the observed behavior. Use fake credentials and account
identifiers only.

## Supported versions

Until the first stable release, only the latest tagged release is supported.
Security fixes may require upgrading the application, host policy, and bundle
schema together.

## Security boundary

`access-env` orchestrates command-scoped credentials; it is not a sandbox.
Processes running as the same unrestricted operating-system user are treated as
trusted peers. Mutually untrusted workloads require separate users, containers,
virtual machines, or a separately trusted broker.

Live registries, host policies, bootstrap credentials, provider credentials,
runtime state, and environment-specific IAM policies must remain outside this
repository.
