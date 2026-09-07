## What this changes

<!-- What the change does, and why. If it fixes something, say what was broken. -->

## Wire format

<!-- Does this change what a token looks like, or which tokens are accepted? If yes, say so
here in the first line: it is a major version and it breaks every deployed integration.
If no, say "unchanged". -->

## Tests

- [ ] `sf apex run test --test-level RunLocalTests --code-coverage` passes on a Developer Edition
- [ ] The six external interop tokens still decrypt (they are in `JweTest`)
- [ ] New behavior has a test that fails without the change

<!-- Paste the test summary: tests run, pass rate, coverage. -->

## Checks

- [ ] `npx prettier --check "force-app/**/*.cls"`
- [ ] `sf code-analyzer run --workspace force-app` reports no violations
- [ ] No key material, initialization vector or plaintext is logged anywhere
- [ ] `docs/` and `specs/` updated if a decision changed
