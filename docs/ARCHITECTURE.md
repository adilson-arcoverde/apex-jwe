# Architecture

The library as it stands: what the parts are, how a token gets built and taken apart, and where
each specification lands. For why the decisions went this way, read [specs/](../specs/); for the
plan that produced this shape, [REFACTOR-DESIGN.md](REFACTOR-DESIGN.md).

## The token

A JWE in Compact Serialization is five base64url strings joined by dots. Each part comes from a
different place, and the diagram below says which:

```
eyJhbGciOiJSU0EtT0FFUC0yNTYi...  .  N4ZZ-bJ94A9Hji...  .  Ybju9HUS...  .  0GAQHHLA...  .  KdbPeGdx...
            header                     encrypted key         IV           ciphertext        tag
              |                              |                |               |               |
   canonical JSON of alg,          the content            16 random     AES-CBC of the    HMAC over
   enc and kid, and also           encryption key         octets        payload under     header, IV,
   the additional                  under the              per message   the ENC half      ciphertext
   authenticated data              recipient's key                      of the CEK        and AL
                                   (empty for dir)
```

The header is the part with two jobs. It travels as the first component, and its octets are the
additional authenticated data of the content encryption, which is what binds the declared
algorithms to the ciphertext. Change one character of the header and the tag stops matching.

## Encrypting

`Jwe.encrypt(payload, key)` runs the assembly of RFC 7516 section 5.1 in this order:

1. Refuse a blank payload, and refuse a key of the wrong kind for the configured `alg`.
2. Serialize the header. `JweHeader.encode()` writes `alg`, `enc` and then `kid` through a JSON
   generator and base64url encodes the result.
3. Obtain the content encryption key. With `dir` it is the caller's symmetric key, checked
   against the length the content encryption expects. Otherwise `JweBytes.random` draws a fresh
   one from the platform CSPRNG.
4. Wrap it. `JweRsaOaep.wrap` pads the key with EME-OAEP and raises it to the public exponent,
   producing exactly as many octets as the modulus. With `dir` this part of the token is empty.
5. Draw the initialization vector, 16 octets, fresh per message.
6. Encrypt and authenticate. `JweAesCbcHmac.encrypt` splits the CEK into a MAC half and an
   encryption half, encrypts with AES-CBC, then computes the tag over the header octets, the IV,
   the ciphertext and the AL field.
7. Join the five parts.

## Decrypting

`Jwe.decrypt(token, key)` follows RFC 7516 section 5.2. The order matters, and each step below
says why it sits where it does:

1. Refuse a key that cannot decrypt at all, with a specific message. A key without its private
   exponent is the caller's mistake and says nothing about the token.
2. Split on dots, keeping empty parts. Anything but five parts is rejected.
3. Decode all five. The header is parsed, `crit` and `zip` are refused, and the other four parts
   are base64url decoded. A failure anywhere here is a rejection, and which part failed is not
   disclosed.
4. Compare the token's algorithms with the configured ones, case sensitively. This happens
   before any key operation, so a token cannot talk the library into an algorithm it was not
   configured for.
5. Obtain the content encryption key. With `dir` the encrypted key part must be empty, and the
   caller's key is used. Otherwise `JweRsaOaep.unwrap` runs, and if it fails, or returns the
   wrong length, random bytes of the right length take its place.
6. Verify the tag, then decrypt. `JweAesCbcHmac.decrypt` computes the tag over what arrived and
   compares it without an early return. Only if it matches does AES run.

Step five is why the failures look alike. A wrapped key that does not unwrap produces a random
CEK, the tag check then fails, and the caller sees the same `JWE decryption failed` as a
tampered ciphertext would produce. See [specs/0004](../specs/0004-uniform-failure-for-received-tokens.md).

## The layers

Dependencies point one way. Nothing in a lower layer knows the layer above it: `JweBigInt` has
never heard of JWE, and `JweBytes` has never heard of RSA.

```
                          Jwe
              the five parts, pinning, uniform failure
                           |
        +------------------+------------------+
        |                  |                  |
   JweHeader        JweKeyEncryption    JweAesCbcHmac
   the header        (interface)          RFC 7518 5.2
        |                  |                  |
        |            JweRsaOaep               |
        |            OAEP + MGF1 + RSA        |
        |                  |                  |
        +---------+--------+---------+--------+
                  |                  |
              JweKey            JweBigInt
              the JWK           Decimal arithmetic
                  |                  |
        +---------+---------+--------+
        |                   |
   JweBase64Url         JweBytes
   RFC 4648 5           immutable octets
```

`JweException` sits outside the diagram: every layer raises it.

## What each type knows

| Type               | Knows                                                                 | Deliberately does not know                  |
| ------------------ | --------------------------------------------------------------------- | ------------------------------------------- |
| `Jwe`              | The token layout, which algorithms are configured, the failure policy | How any algorithm works                     |
| `JweHeader`        | The header members and their canonical order                          | Which algorithm names are supported         |
| `JweKey`           | JWK members, RSA and oct                                              | Where the key came from or how it is stored |
| `JweKeyEncryption` | Nothing, it is the contract                                           |                                             |
| `JweRsaOaep`       | EME-OAEP, MGF1, the RSA primitive                                     | Tokens, headers, content encryption         |
| `JweAesCbcHmac`    | The AEAD composition and its three profiles                           | Key management, tokens                      |
| `JweBytes`         | Octets, and the operations padding needs                              | What the octets mean                        |
| `JweBase64Url`     | RFC 4648 section 5                                                    | What is being encoded                       |
| `JweBigInt`        | Modular arithmetic over `Decimal`                                     | RSA, padding, keys                          |

## Why there is a byte string type

Apex gives no indexed access to `Blob`. There is no way to read octet seventeen of a blob, and
OAEP is defined entirely in terms of octet positions: a label hash, then zeros, then a `0x01`
separator, then the message, all masked by a generated stream.

`JweBytes` holds the octets as a `List<Integer>` and uses hex as the only bridge to and from
`Blob`, through `EncodingUtil`. Instances are immutable, so an operation returns a new byte
string and a caller holding key material cannot have it changed underneath.

Hex appears in exactly two places for that reason: at the `Blob` boundary, and in
`JweKey.fromSecretHex`, because a pre-shared secret usually arrives written that way. Everywhere
else the transport format between methods is octets.

## Where the arithmetic goes

RSA needs numbers with 617 decimal digits, and Apex has no big integer type. `JweBigInt` stands
one up on `Decimal`, restricted to whole numbers:

- `modPow` is square and multiply. Parity comes from the low 64 bits of the exponent, because
  truncating a wider `Decimal` cannot change its last bit.
- `modPowCrt` is the Chinese Remainder Theorem recombination, two exponentiations of half the
  size, which is what brings a 2048 bit decryption inside the CPU limit.
- `mod` is a remainder from floor division, which gives a non-negative result for a negative
  dividend and is what the CRT step needs.
- `fromHex` parses in Horner form, and `toHex(octets)` is I2OSP: it left pads to the exact
  length and refuses a value that does not fit, because an RSA ciphertext of the wrong length is
  not a ciphertext.

## Where each RFC lands

| Specification | Section                        | Implemented in                 |
| ------------- | ------------------------------ | ------------------------------ |
| RFC 7516      | 5.1, assembly                  | `Jwe.encrypt`                  |
| RFC 7516      | 5.2, decryption and its checks | `Jwe.decrypt`                  |
| RFC 7516      | 11.5, failure handling         | `Jwe.unwrapOrSubstitute`       |
| RFC 7518      | 4.3, RSA-OAEP key management   | `JweRsaOaep`                   |
| RFC 7518      | 4.5, direct encryption         | `Jwe`, the `dir` branch        |
| RFC 7518      | 5.2, AES-CBC with HMAC-SHA-2   | `JweAesCbcHmac`                |
| RFC 7518      | 6.3 and 6.4, RSA and oct keys  | `JweKey`                       |
| RFC 7515      | 4.1.1, header parameter rules  | `JweHeader`                    |
| RFC 8017      | 7.1, RSAES-OAEP                | `JweRsaOaep`                   |
| RFC 8017      | 4.1 and 4.2, I2OSP and OS2IP   | `JweBigInt`, `JweBytes.i2osp4` |
| RFC 8017      | B.2.1, MGF1                    | `JweRsaOaep.mgf1`              |
| RFC 4648      | 5, base64url                   | `JweBase64Url`                 |

## What it costs to run

The RSA arithmetic runs in interpreted Apex, so the cost is visible. Measured with
`Limits.getCpuTime()` on RSA-2048 and small payloads, against a 10,000 ms synchronous limit:

| Operation            | CPU           |
| -------------------- | ------------- |
| `dir` encrypt        | 14 ms         |
| `dir` decrypt        | 12 ms         |
| RSA-OAEP-256 encrypt | 58 ms         |
| RSA-OAEP-256 decrypt | 147 to 176 ms |

Decryption is the expensive direction because the private exponent is 2048 bits against the 17
of the public one, and that is with the CRT path already halving the work. The content
encryption cost grows with the payload while the RSA cost stays flat, so a large payload under
`dir` stays cheap while a small payload under RSA-OAEP still pays for the key operation.

One token per transaction fits comfortably. Several RSA tokens in the same transaction will run
past the limit, and the way around that is a queueable per token rather than a faster algorithm.

## What is not here

This library does not sign anything. Salesforce provides `Auth.JWS` for that.

It does not generate keys either. Apex cannot produce an RSA key pair, so a JWK has to come from
outside, and the library reads one rather than making one.

It also has no opinion on where that key was kept. `encrypt` and `decrypt` take a `JweKey` and
stop there, which is the subject of
[specs/0005](../specs/0005-algorithms-configure-keys-are-arguments.md).

The algorithms it declines are GCM, ECDH-ES, AES-KW, PBES2, `RSA1_5` and compression, and
[specs/0003](../specs/0003-supported-algorithm-matrix.md) gives the reasoning for each of them.

Deploying it brings ten Apex classes and nothing else: no custom objects, no custom settings,
no named credentials, no remote site settings.
