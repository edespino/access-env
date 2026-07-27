## Summary

<!-- Describe the change and why it is needed. -->

## Verification

<!-- List exact tests and checks run. -->

- [ ] Focused regression or validation completed
- [ ] Full test suite completed
- [ ] `git diff --check` passed
- [ ] Security-sensitive changes received independent review

## Security and repository boundary

- [ ] No credentials, tokens, private keys, live bundle contents, `op://` references, account identifiers, environment dumps, or sensitive logs are included
- [ ] Examples use deliberate placeholders only
- [ ] Filesystem, process, installer, policy, or CI trust-boundary changes fail closed
- [ ] CI changes do not introduce unreviewed external side effects

## Release or operational impact

<!-- Note compatibility, installation, rollback, or release implications. Write "None" when not applicable. -->
