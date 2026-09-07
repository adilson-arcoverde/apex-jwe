# apex-jwe

JSON Web Encryption (RFC 7516) in native Apex. Compact Serialization, RSA-OAEP and direct key
agreement, AES-CBC with HMAC-SHA-2 content encryption. No callouts, no external service, no
dependencies.

```apex
Jwe jwe = new Jwe(new JweHeader('RSA-OAEP-256', 'A256CBC-HS512').withKeyId('2026-09'));

String token = jwe.encrypt('{"sub":"1234"}', JweKey.fromJson(publicJwk));
String payload = jwe.decrypt(token, JweKey.fromJson(privateJwk));
```

## Why this exists

Salesforce gives Apex a `Crypto` class with AES in CBC mode, HMAC, digests and RSA signing, and
an `Auth.JWS` class for signed JWTs. None of that encrypts a payload with someone else's public
key. There is no RSA-OAEP, and there is no JWE.

That becomes a problem the moment an integration requires message level encryption, which is
common in payments and in government interfaces: the counterparty publishes a JWK and expects a
five part token, and the platform has nothing to build one with. The remaining options are to
send the plaintext to an external service so that it can do the encryption, which gives away the
thing the encryption was protecting, or to implement JWE in Apex.

This code was written for the second option, inside a client integration in 2021. It has been
interoperating with a real counterparty since then, and was rewritten for publication with its
behavior frozen by test vectors first (see [specs/0001](specs/0001-rewrite-with-behavior-frozen-first.md)).

As far as we can tell it is the first public implementation of JWE with RSA-OAEP in native Apex.
The earliest commit of this code that we can date is from August 2021, in a private repository;
the only public native-Apex RSA-OAEP implementation we could find is from March 2023, and it
implements the primitive rather than the token format. We would be glad to be corrected.

## Installing it in your org

Nothing to install first. Clone the repository and deploy the source, replacing the placeholder
with your own org alias:

```bash
git clone https://github.com/adilson-arcoverde/apex-jwe.git
cd apex-jwe

sf project deploy start --source-dir force-app --target-org <YOUR_ORG_ALIAS>
```

Then run the suite in that org to see the library prove itself:

```bash
sf apex run test --target-org <YOUR_ORG_ALIAS> --test-level RunLocalTests --code-coverage --wait 30
```

The project declares API version 67.0. Ten Apex classes go in, plus the test classes, and
nothing else: no custom objects, no custom settings, no remote site settings, no named
credentials.

If you would rather keep the test classes out of a production org, deploy only what the library
needs:

```bash
sf project deploy start --target-org <YOUR_ORG_ALIAS> \
  --metadata ApexClass:Jwe ApexClass:JweHeader ApexClass:JweKey ApexClass:JweKeyEncryption \
             ApexClass:JweRsaOaep ApexClass:JweAesCbcHmac ApexClass:JweBytes \
             ApexClass:JweBase64Url ApexClass:JweBigInt ApexClass:JweException
```

## Using it

Key wrapping, where the recipient publishes an RSA public key and you generate a content
encryption key per message:

```apex
Jwe jwe = new Jwe(new JweHeader('RSA-OAEP-256', 'A256CBC-HS512'));

// Encrypting needs n and e. Decrypting also needs d, and uses p, q, dp, dq and qi when present.
String token = jwe.encrypt(payload, JweKey.fromJson(publicJwk));
String back = jwe.decrypt(token, JweKey.fromJson(privateJwk));
```

Direct encryption, where both sides already hold the content encryption key:

```apex
Jwe shared = new Jwe(new JweHeader('dir', 'A256CBC-HS512'));

// A shared key is a JWK with kty of oct (RFC 7518 section 6.4). fromSecretHex is a shortcut
// for the hex form a pre-shared secret usually arrives in: MAC key followed by encryption key.
String token = shared.encrypt(payload, JweKey.fromSecretHex(sharedKeyHex));
```

The algorithms live in the constructor and the key is an argument, because a recipient decides
in advance which algorithms it accepts while keys belong to messages. One instance therefore
serves many keys, and the library never holds key material between calls. Where your keys are
stored is your decision and none of this library's business, so it reads a JWK and stops there
(see [specs/0005](specs/0005-algorithms-configure-keys-are-arguments.md)).

Where to keep a private key: protected custom metadata, or behind a named credential. Not in an
Apex class, and not in a custom setting a user can query.

## What it supports

| Header | Supported                                         | Not supported                                     |
| ------ | ------------------------------------------------- | ------------------------------------------------- |
| `alg`  | `dir`, `RSA-OAEP`, `RSA-OAEP-256`                 | `RSA1_5`, `A*KW`, `A*GCMKW`, `ECDH-ES*`, `PBES2*` |
| `enc`  | `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` | `A*GCM`                                           |

A token asking for anything else is rejected rather than partly honoured, and so is one carrying
`zip` or `crit`. The GCM family is absent because the platform cannot do it: `Crypto` offers AES
in CBC mode only. `RSA1_5` is absent on purpose, since PKCS#1 v1.5 key transport is what
Bleichenbacher's attack targets. The reasoning for each line is in
[specs/0003](specs/0003-supported-algorithm-matrix.md).

This library does not sign. For JWS, Salesforce provides `Auth.JWS` natively.

## What it costs

RSA on this platform is arithmetic in interpreted code, because Apex has no big integer type and
`Decimal` is what stands in for one. Measured with `Limits.getCpuTime()` on an RSA-2048 key and
small payloads, against the 10,000 ms synchronous limit:

| Operation            | CPU           |
| -------------------- | ------------- |
| `dir` encrypt        | 14 ms         |
| `dir` decrypt        | 12 ms         |
| RSA-OAEP-256 encrypt | 58 ms         |
| RSA-OAEP-256 decrypt | 147 to 176 ms |

Decryption costs more than encryption because the private exponent is 2048 bits against the 17
of the public one, and that is with the CRT path already halving the work. Budget one token per
transaction. A loop over many RSA tokens in a single transaction will not fit, and the fix is a
queueable per token rather than a faster algorithm. Direct encryption is an order of magnitude
cheaper, which is why it is worth using when a shared key is appropriate.

## What it does for your security

- The configured header decides the algorithms. A token declaring different ones is rejected,
  so a sender cannot talk you into a weaker algorithm than you agreed to.
- The content encryption key and the initialization vector are drawn per message from the
  platform CSPRNG.
- Every failure that depends on the content of a received token reports the same message. A
  wrapped key that does not unwrap is replaced by random bytes so the failure lands on the
  authentication tag, which is what denies an attacker the oracle that Bleichenbacher-style
  attacks need (RFC 7516 section 11.5).
- The tag is compared without an early return.
- A CRT decryption is verified by re-encrypting under the public exponent, because a faulty CRT
  result discloses the factorisation of the modulus.
- Nothing is logged. No key material, no initialization vector, no plaintext.

The limits are documented too, in [specs/0004](specs/0004-uniform-failure-for-received-tokens.md):
the padding checks inside OAEP cannot be made constant time in Apex, and the random key
substitution is what removes the value of the timing difference that remains.

## How it is tested

128 tests, 100% coverage, and the part that matters is where the test data comes from. A round
trip proves only that a library agrees with itself, so behavior is pinned by values produced
elsewhere: the RFC 7518 Appendix B vectors for all three content encryptions, the RFC 8017
EME-OAEP and MGF1 vectors, the RFC 4648 base64 vectors, and six complete tokens generated
outside Apex by two independent implementations.

Tokens produced by this library have also been read back by three other implementations, which
is the direction an Apex test suite cannot cover on its own. Details in
[specs/0007](specs/0007-freeze-behavior-with-external-vectors.md) and
[docs/TEST-VECTORS.md](docs/TEST-VECTORS.md).

## Reading the code

Ten types, each small enough to read in one sitting.

| Type               | Responsibility                                                                                    |
| ------------------ | ------------------------------------------------------------------------------------------------- |
| `Jwe`              | The facade: assembles and parses the five parts, pins the algorithms, applies the uniform failure |
| `JweHeader`        | The protected header: canonical JSON, parsing, algorithm comparison                               |
| `JweKey`           | A JWK, RSA or oct, and the accessors the algorithms need                                          |
| `JweKeyEncryption` | The interface a key management algorithm implements                                               |
| `JweRsaOaep`       | RSAES-OAEP: EME-OAEP encoding, MGF1, and the RSA primitive                                        |
| `JweAesCbcHmac`    | The AEAD composition of RFC 7518 section 5.2                                                      |
| `JweBytes`         | An immutable byte string, since Apex has no indexed access to `Blob`                              |
| `JweBase64Url`     | Base64URL without padding, strict on decode                                                       |
| `JweBigInt`        | Modular arithmetic over `Decimal`, because Apex has no big integer                                |
| `JweException`     | The one exception type                                                                            |

Three documents answer different questions. [specs/](specs/) records why each decision was made.
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) describes how the pieces fit together.
[docs/REFACTOR-DESIGN.md](docs/REFACTOR-DESIGN.md) is the plan that was executed to get here,
including every deviation decided along the way.

## Standards

| RFC                                            | What it defines        | Used for                                                               |
| ---------------------------------------------- | ---------------------- | ---------------------------------------------------------------------- |
| [7516](https://www.rfc-editor.org/rfc/rfc7516) | JSON Web Encryption    | The token format, the five parts, the failure handling of section 11.5 |
| [7518](https://www.rfc-editor.org/rfc/rfc7518) | JSON Web Algorithms    | `alg` and `enc` values, the AES-CBC with HMAC composition, JWK members |
| [7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key           | The key format this library reads                                      |
| [7515](https://www.rfc-editor.org/rfc/rfc7515) | JSON Web Signature     | Header parameter rules, including their case sensitivity               |
| [8017](https://www.rfc-editor.org/rfc/rfc8017) | PKCS #1 version 2.2    | RSAES-OAEP, MGF1, I2OSP and OS2IP                                      |
| [4648](https://www.rfc-editor.org/rfc/rfc4648) | Base16, Base32, Base64 | Base64URL, section 5, and its test vectors in section 10               |

## Related work and credits

Big integer arithmetic is the part of RSA that Apex does not give you, and it has been passed
hand to hand through public gists since 2016. This library is on that chain, and so is everyone
else's:

- [karmats](https://gist.github.com/karmats/4270441be5a34fff7062), February 2016. Modular
  exponentiation over `Decimal`, with PKCS#1 v1.5 padding. Encryption only.
- [nikitakarpenkov](https://gist.github.com/nikitakarpenkov/7a39c5cd6170dbcac74cf797d03e60f7),
  March 2018. The same helpers, with decryption added. Reposted by
  [vasudevanselvaganesh](https://gist.github.com/vasudevanselvaganesh/7a817e58a5c703ece149da70cbb1553a)
  in June 2019.
- [alex-shekhter/apex-crypto-rsa-oaep-sha256](https://github.com/alex-shekhter/apex-crypto-rsa-oaep-sha256),
  Apache-2.0, March 2023. RSAES-OAEP with SHA-256, on the same arithmetic base, stopping at the
  primitive.

The 2021 implementation this library was rewritten from carried those arithmetic helpers too:
the same four private methods, under the same names, two of them identical line for line to the
2016 gist. That shared ancestor is why the four projects resemble each other in their lowest
layer, and it is older than all of them.

What sits on top of that base appears in none of the gists: EME-OAEP encoding and decoding,
MGF1, CRT decryption with a fault check, and the entire JWE layer, meaning the compact
serialization, the AEAD composition of RFC 7518 section 5.2, algorithm pinning, and the failure
handling of RFC 7516 section 11.5.

`JweBigInt` was written for this release. It implements the same textbook algorithms, because
square and multiply, base conversion by repeated division and a remainder from floor division
are what the platform leaves room for. Of what came down the chain, the remainder helper is two
lines that Apex admits in essentially one form, and the base conversion loop has been rewritten
to collect character codes rather than prepend to a string, which is a different expression and
also linear instead of quadratic. The gists carry no license, so nothing from them is
redistributed here, and the credit above is the debt this library does owe.

One other class, a byte array helper, was adapted from a source whose origin could not be
traced, and was rewritten from scratch for that reason.
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) records what was found and what was done about
it. If you recognise your work in any of this, please open an issue so the credit can go where
it belongs.

The test vectors are not ours either. They come from the RFCs listed above and from tokens
generated with [jose](https://github.com/panva/jose) on Node.

## Reporting a problem

For anything with a security dimension, use GitHub's private vulnerability reporting from the
Security tab rather than a public issue. [SECURITY.md](SECURITY.md) says what is in scope, what
is not, and which limitations are documented rather than fixed.

## How this was written

The code and the documents here were drafted with an AI assistant. The decisions were the
author's, and the ones worth arguing with are in [specs/](specs/) with the reasoning attached,
including the two claims that turned out to be wrong and what replaced them.

## License

Apache License 2.0. Use it, change it, ship it, including in commercial work. What the license
asks in return is that you keep the copyright and license notices and say what you changed. The
full terms are in [LICENSE](LICENSE), and [NOTICE](NOTICE) carries the attribution that Apache
2.0 asks a redistributor to pass along.

The source files carry no license header. The notice lives in `LICENSE` and `NOTICE`, which is
what the license requires, and a header on each of ten small classes would be three lines of
ceremony at the top of every one. Why this license and not a restrictive one is recorded in
[specs/0008](specs/0008-apache-2-0.md).

Copyright 2026 Adilson Arcoverde.
