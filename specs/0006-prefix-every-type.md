# 0006: Prefix every type with `Jwe`

- Status: Accepted
- Date: 2026-09-07
- Deciders: the author

## Context

Apex has no namespaces outside managed packages. A library installed as source into somebody
else's org puts its class names straight into a flat global space, next to whatever is there
already.

The natural names for the pieces of this library are the names an org has most likely taken:
`Base64Url`, `ByteArray`, `Header`, `Key`, `BigInt`. A collision is a deploy that fails, or a
deploy that succeeds and binds to somebody else's `Header`.

## Decision

Every type carries the `Jwe` prefix: `Jwe`, `JweHeader`, `JweKey`, `JweKeyEncryption`,
`JweRsaOaep`, `JweAesCbcHmac`, `JweBytes`, `JweBase64Url`, `JweBigInt`, `JweException`.

Ten types where the original had four. Each is small enough to read in one sitting and has one
reason to change.

## Consequences

- The facade is called `Jwe`, so the common case reads as `new Jwe(header)` and not as a stutter.
- The old names are gone, with no aliases. `RSA_OAEP` was a public name in the original, and
  dropping it is a breaking change that costs nothing here, since nothing outside this
  repository ever depended on it.
- Inside the library the prefix reads as redundant, because every type has it. That is the price
  of protecting the consumer's namespace, and the consumer is who matters.
- If this ever ships as a managed package, the namespace would make the prefix genuinely
  redundant. Removing it then would be a breaking change, so it stays either way.
