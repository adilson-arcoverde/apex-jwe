# Changelog

Notable changes to this library. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the numbering follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), where the public surface is the ten
`Jwe` types and the wire format of the tokens they produce. A change to either is a major
version.

## [1.0.0] - 2026-09-07

First public release. The code is older than the release: it was written for a client
integration in 2021, has been interoperating with a counterparty since then, and was rewritten
for publication with its behavior frozen by test vectors before anything moved.

### Added

- `Jwe`, which builds and reads JWE tokens in Compact Serialization (RFC 7516).
- Key management with `dir`, `RSA-OAEP` and `RSA-OAEP-256`, the RSA cases running on
  EME-OAEP and MGF1 over `Decimal` arithmetic, with a CRT decryption path.
- Content encryption with `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512`, the AEAD
  composition of RFC 7518 section 5.2.
- `JweKey`, which reads RSA and `oct` keys from JWK, and `JweKey.fromSecretHex` for a
  pre-shared secret in the form one usually arrives in.
- `JweHeader`, with canonical serialization through a JSON generator and strict parsing that
  refuses `crit` and `zip` rather than ignoring them.
- 128 tests. Behavior is pinned by the RFC 7518 Appendix B vectors for all three content
  encryptions, the RFC 8017 EME-OAEP and MGF1 vectors, the RFC 4648 base64 vectors, and six
  complete tokens produced outside Apex by two independent implementations.

### Security

- The configured header pins the algorithms, and a token declaring different ones is rejected
  before any key operation.
- The content encryption key and the initialization vector are drawn per message from the
  platform CSPRNG.
- A wrapped key that fails to unwrap is replaced by random bytes, so the failure surfaces at the
  authentication tag rather than telling an attacker that the unwrap itself failed
  (RFC 7516 section 11.5).
- Every failure that depends on the content of a received token carries the same message, while
  a caller's own mistake says what is wrong.
- The authentication tag and the OAEP label hash are compared without an early return.
- A CRT decryption is verified by re-encrypting under the public exponent, because a faulty
  result would disclose the factorisation of the modulus.
- No key material, initialization vector or plaintext is ever logged.

### Notes

- `RSA1_5` is not implemented, and will not be: it is the algorithm Bleichenbacher's attack
  targets. The GCM family is not implemented because `Crypto` offers AES in CBC mode only.
- Requires API version 67.0. No custom objects, custom settings, named credentials or remote
  site settings, and no dependencies at runtime.
- An RSA-2048 unwrap costs 147 to 176 ms of CPU, measured with `Limits.getCpuTime()`. Budget one
  token per transaction.
