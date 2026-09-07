# Third party notices

This library redistributes no third party code. Everything in `force-app/` was written for this
project and is covered by [LICENSE](LICENSE). What follows is what the code owes anyway, and
what was checked before saying so.

## Big integer arithmetic, and a gist from 2016

Apex has no big integer type, so every RSA implementation on the platform has had to build
modular arithmetic over `Decimal`. That code has been passed hand to hand through public gists,
and the earliest one this project could find is by
[karmats](https://gist.github.com/karmats/4270441be5a34fff7062), published on 23 February 2016.
It carries four private helpers, `hexToDecimal`, `decimalToHex`, `modPow` and `modulus`, with
the constants `DIGITS` and `HEX_BASE`.

Those four names, and those two constants, appear in the 2021 implementation this library was
rewritten from. Comparing them on 7 September 2026: `decimalToHex` and `modulus` were identical
line for line, `modPow` differed in one comparison operator, and `hexToDecimal` had been
rewritten into Horner form. The same helpers appear in a
[2018 gist by nikitakarpenkov](https://gist.github.com/nikitakarpenkov/7a39c5cd6170dbcac74cf797d03e60f7),
reposted by
[vasudevanselvaganesh](https://gist.github.com/vasudevanselvaganesh/7a817e58a5c703ece149da70cbb1553a)
in 2019, and three of them in
[alex-shekhter/apex-crypto-rsa-oaep-sha256](https://github.com/alex-shekhter/apex-crypto-rsa-oaep-sha256)
(Apache-2.0, March 2023). Four projects, one ancestor.

The gists carry no license, which under GitHub's terms of service means the author kept all
rights. So the arithmetic was rewritten for this release as `JweBigInt`, which is why nothing
from the gists is redistributed:

- Base conversion collects character codes and reverses them once, rather than prepending each
  digit to a growing string.
- Hex parsing uses Horner's method, one multiplication and one addition per digit.
- Square and multiply, the Chinese Remainder Theorem recombination and the fault check are
  textbook constructions from RFC 8017 and the standard cryptography literature.
- The remainder helper is two lines built on floor division, and Apex admits it in essentially
  one form. Where the platform leaves no room for a second expression, this one looks like
  everyone else's.

What was built on top of that base appears in none of the gists: EME-OAEP encoding and decoding,
MGF1, the CRT fault check, and the whole JWE layer.

The credit here is voluntary rather than required, and it is owed. If you are the author of any
of the work above and would rather this read differently, please open an issue.

## A byte array helper of unknown origin

The implementation this library replaced contained a `ByteBlob` class, a wrapper over
`List<Integer>` with `concat`, `xor`, `copyOfRange` and random byte generation. It had been
adapted from somewhere, and the author no longer remembered where.

The origin was searched for on 7 September 2026, with GitHub code search for
`class ByteBlob language:Apex` and for `ByteBlob fromByteArray`, and with a web search for
literal comment strings from the file. Nothing public came back.

Since a credit could not be placed, the class was rewritten from scratch as `JweBytes`, which
is immutable, has a different API and shares no code with what came before. If you recognise
your work in it, please open an issue so the credit can go where it belongs.

## Test vectors

The vectors that pin this library's behavior are not ours, and that is the point of them.

- RFC 7518 Appendix B, all three AES-CBC with HMAC cases. RFC 8017, the EME-OAEP and MGF1
  vectors. RFC 4648 section 10, the Base64 vectors. These are published as part of the
  specifications by the IETF Trust.
- Six complete tokens generated outside Apex, four with [jose](https://github.com/panva/jose)
  (MIT) on Node and two with the Node `crypto` module. `jose` is a development dependency used
  to produce those tokens and to verify tokens this library produces. It is not redistributed
  and no part of it is deployed to a Salesforce org.
- The RSA key pairs in the test classes were generated for this repository and are documented as
  throwaway keys. They protect nothing.

Provenance for every vector is recorded in [docs/TEST-VECTORS.md](docs/TEST-VECTORS.md).

## Development dependencies

`package.json` declares `jose` (MIT), `prettier` (MIT) and `prettier-plugin-apex` (MIT). They
generate test vectors and format Apex source. None of them is part of what gets deployed.
