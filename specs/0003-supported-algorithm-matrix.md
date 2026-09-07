# 0003: Support three content encryptions and two key wraps, and no more

- Status: Accepted
- Date: 2026-09-07
- Deciders: the author

## Context

JWE defines a wide algorithm vocabulary. What a library on this platform can offer is limited by
what `Crypto` exposes, and what it should offer is a separate question from that.

## Decision

| Header | Supported                                         | Not supported                                     |
| ------ | ------------------------------------------------- | ------------------------------------------------- |
| `alg`  | `dir`, `RSA-OAEP`, `RSA-OAEP-256`                 | `RSA1_5`, `A*KW`, `A*GCMKW`, `ECDH-ES*`, `PBES2*` |
| `enc`  | `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` | `A*GCM`                                           |

Nothing outside that table is accepted, and a token asking for something else is rejected
instead of partly honoured. The same goes for the two header parameters that change how a
payload has to be processed. `zip` is refused because a plaintext this library did not inflate
is not the plaintext. `crit` is refused because it exists to say that ignoring a member is not
acceptable.

## Consequences

GCM is out because the platform cannot do it. `Crypto` offers AES in CBC mode only. Implementing
GCM in Apex would mean Galois field multiplication in interpreted code, which would not survive
the CPU limit. This was checked on the validation org rather than assumed.

`RSA1_5` is out on purpose. PKCS#1 v1.5 key transport is the algorithm Bleichenbacher's attack
targets, and JOSE keeps it only for compatibility with deployed systems. A new library has no
such compatibility to keep.

`A192CBC-HS384` is in, and it nearly was not. The design document asserted that Apex has no
AES-192, and the RFC 7518 Appendix B.2 vector had been parked as a documented negative case on
that basis. The assertion was false. `Crypto.encrypt` accepts `AES192` and `Crypto.generateMac`
accepts `hmacSHA384`. Supporting the algorithm cost one entry in a map, and the vector that had
been sitting there as an excuse now passes octet for octet, which completes Appendix B.

That last point is written down rather than quietly fixed, because the mistake is easy to repeat.
A limit attributed to the platform is a claim, and in a cryptographic library a claim of that
kind has to be executed before it is documented.

`RSA-OAEP` uses SHA-1, which JOSE fixes and which is not this library's choice. It is offered
because tokens in the field use it. New integrations should pin `RSA-OAEP-256`.
