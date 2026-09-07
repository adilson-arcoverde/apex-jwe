# 0004: One failure message for anything a token controls

- Status: Accepted
- Date: 2026-09-07
- Deciders: the author

## Context

A decryption can fail for many reasons. The token is malformed, the algorithms are not the ones
expected, the wrapped key does not unwrap, the padding inside it is wrong, the authentication tag
does not match, the plaintext is not valid UTF-8.

Reporting which one happened helps whoever is debugging the integration, and it also hands an
attacker an oracle. Anyone who can tell "the wrapped key did not unwrap" from "the tag did not
match" can recover a plaintext one query at a time. That is the shape of Bleichenbacher's attack
against RSA key transport, and of the padding oracle attacks against CBC.

## Decision

Everything that depends on the content of a received token raises `JweException` with the same
message, `JWE decryption failed`. Nothing distinguishes the cases.

Everything that does not depend on attacker input says what is wrong: an unsupported algorithm,
a key of the wrong kind, a shared key of the wrong length, a key without its private exponent.
Those are the caller's own mistakes, and hiding them helps nobody.

A wrapped key that fails to unwrap is not reported at all. It is replaced by random bytes of the
correct length, and the decryption goes on to fail at the authentication tag, the same way a
tampered ciphertext would (RFC 7516 §11.5).

## Consequences

- The tag comparison accumulates differences instead of returning at the first one, so it does
  not leak how many leading octets were right. The OAEP label hash gets the same treatment,
  since a chosen ciphertext influences it too.
- Padding checks inside OAEP cannot be made constant time in Apex, so one decoding failure is
  still distinguishable from another by timing. The random key substitution is what takes the
  value out of that distinction. The limitation is documented in the class instead of being
  glossed over.
- Debugging a rejected token is harder by design. The library never logs key material, an
  initialization vector or a plaintext, so a failing integration is diagnosed by reproducing it
  with a known good token, not by reading a log.
- Five test methods assert the uniform message across seventeen cases: eight malformed tokens,
  three tampered parts, three algorithm mismatches, a `dir` token carrying a wrapped key, the
  wrong shared key, and a wrapped key that cannot unwrap. Anything that starts reporting more
  than that breaks a test.
