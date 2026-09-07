# 0007: Prove the wire format with vectors this project did not produce

- Status: Accepted
- Date: 2026-09-07
- Deciders: the author

## Context

A round trip test proves that a library agrees with itself. It would pass just as happily if the
whole token format had been invented here, which for an interoperability format is the one thing
that must not be true.

The original test suite was in that position. It covered the code thoroughly and pinned almost
nothing an outside party could verify.

## Decision

Behavior is frozen by values produced elsewhere, and the suite fails if any of them stops
reading:

| Source                                              | What it pins                                                                                |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| RFC 7518 Appendix B.1, B.2, B.3                     | The AES-CBC with HMAC composition: key split, AL field, tag truncation, all three key sizes |
| RFC 8017 EME-OAEP and MGF1 vectors                  | The padding, seed by seed, for SHA-1 and SHA-256                                            |
| RFC 4648 §10                                        | Base64URL, including the two code points where the alphabets differ                         |
| Four tokens from `jose` on Node                     | End to end decryption, across the `alg` and `enc` matrix                                    |
| Two tokens from the Node `crypto` module            | The same, from a second independent producer                                                |
| A throwaway RSA-512 key with a published ciphertext | The modular arithmetic, with no padding involved                                            |

Where a vector fixes a random input, the input is injectable so the vector can be reproduced.
The OAEP seed is a parameter of the encoding, and the initialization vector can be injected for
one message and is then discarded.

## Consequences

- Six externally produced tokens have to keep decrypting to their published payloads. When a
  change breaks the wire format, that is what fails, and it fails before anything else.
- The direction the suite cannot cover on its own is a token produced here and read elsewhere,
  because the verifier would have to be the other implementation. During the migration this was
  covered by crossing tokens with the implementation being replaced, in both directions. After
  that code was deleted, the crossing was done by hand against `jose` for `dir` and
  `RSA-OAEP-256`, and against a browser based JOSE tool for `RSA-OAEP-256` with both
  A128CBC-HS256 and A256CBC-HS512.
- Three independent implementations have now read or written tokens this library agreed with.
- Every vector lives in one place, `JweTestKeys` or `JweTestTokens`, and `docs/TEST-VECTORS.md`
  records where each one came from. A vector kept in two places is one that can drift out of
  agreement with itself.
- Regenerating the interop tokens is a deliberate act. `scripts/generate-interop-vectors.mjs`
  exists for it, and a change in its output means the wire format moved.
