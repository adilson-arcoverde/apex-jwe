# 0002: Run the RSA arithmetic on `Decimal`

- Status: Accepted
- Date: 2026-09-07
- Deciders: the author

## Context

RSA-OAEP needs modular exponentiation over integers the size of the modulus: 2048 bits, or 617
decimal digits. Apex has no big integer type. `Long` stops at 64 bits and `Integer` at 32, and
there is no platform primitive for RSA with OAEP padding that a library can call instead.

`Decimal` is arbitrary precision. Restricted to whole numbers it can hold a 2048 bit value and
multiply two of them, which is what the RSA primitive needs.

## Decision

Implement the arithmetic as a type of its own, `JweBigInt`, over `Decimal`: modular
exponentiation by square and multiply, Chinese Remainder Theorem recombination with a fault
check, floor modulo, and the OS2IP and I2OSP conversions of RFC 8017.

Keep it apart from the padding scheme so it can be verified against plain number theory instead
of only through OAEP round trips.

## Consequences

- The cost is real and has to be budgeted. Measured with `Limits.getCpuTime()` on RSA-2048, a
  wrap costs around 60 ms of CPU and an unwrap 150 to 180 ms through the CRT path, against a 10
  second synchronous limit. The library is built for one token per transaction, and the class
  documentation says so.
- `dir` costs 12 to 14 ms, because it performs no key management at all. That difference is a
  reason to keep `dir` supported rather than treat it as a curiosity.
- The CRT path is not an optimisation that can be skipped. Two exponentiations of half the size
  are what bring an unwrap inside the limit.
- A CRT result is verified by re-encrypting it under the public exponent before it is returned.
  A miscomputation on one of the two factors would otherwise disclose the factorisation of the
  modulus, which is the Bellcore fault attack. A key whose CRT members disagree with `n` is
  rejected, and a test builds exactly such a key.
- Because the arithmetic is its own type, it is tested against a throwaway RSA-512 key pair with
  a published ciphertext, and against known modular exponentiation results, with no padding
  involved.
