# Test vectors

Published vectors used to pin behavior during the refactoring. Values are hex unless stated.
The Apex test classes embed these constants; this file is the human-readable index and the record of where each vector came from.

## RFC 7518 Appendix B — AES_CBC_HMAC_SHA2

Same P, IV, A and AL across the three cases, and all three are round-trip vectors: the library supports `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512`.

B.2 was originally kept as a negative case, on the belief that Apex had no AES-192. That was wrong: `Crypto.encrypt` accepts `AES192` and `Crypto.generateMac` accepts `hmacSHA384`, both verified on the validation org on 2026-09-07, and the vector has passed ever since.

Embedded in `JweAesCbcHmacTest`, which reproduces E and T of B.1 and B.3 octet for octet and recomputes the B.1 tag independently to pin the MAC input as `AAD || IV || E || AL`. P is 128 octets, so E is 144: CBC adds a full block of PKCS#7 padding.

Shared values:

```text
P  = 41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365
IV = 1af38c2dc2b96ffdd86694092341bc04
A  = 546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673
AL = 0000000000000150
```

### B.1 — A128CBC-HS256

```text
K       = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
MAC_KEY = 000102030405060708090a0b0c0d0e0f
ENC_KEY = 101112131415161718191a1b1c1d1e1f
E       = c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db
M       = 652c3fa36b0a7c5b3219fab3a30bc1c4e6e54582476515f0ad9f75a2b71c73ef
T       = 652c3fa36b0a7c5b3219fab3a30bc1c4
```

### B.2 — A192CBC-HS384

```text
K       = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
MAC_KEY = 000102030405060708090a0b0c0d0e0f1011121314151617
ENC_KEY = 18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
E       = ea65da6b59e61edb419be62d19712ae5d303eeb50052d0dfd6697f77224c8edb000d279bdc14c1072654bd30944230c657bed4ca0c9f4a8466f22b226d1746214bf8cfc2400add9f5126e479663fc90b3bed787a2f0ffcbf3904be2a641d5c2105bfe591bae23b1d7449e532eef60a9ac8bb6c6b01d35d49787bcd57ef484927f280adc91ac0c4e79c7b11efc60054e3
T       = 8490ac0e58949bfe51875d733f93ac2075168039ccc733d7
```

### B.3 — A256CBC-HS512

```text
K       = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
MAC_KEY = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
ENC_KEY = 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
E       = 4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930930806d0703b1f6
M       = 4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5fd30a565c616ffb2f364baece68fc40753bcfc025dde3693754aa1f5c3373b9c
T       = 4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5
```

Source: https://www.rfc-editor.org/rfc/rfc7518#appendix-B

## RFC 8017 / PKCS#1 v2.1 — EME-OAEP and MGF1

Fixed message and seed with k = 128 for SHA-1 and SHA-256, and an MGF1 SHA-1 mask vector. Embedded in `JweRsaOaepTest`, which reproduces the same encoded messages the replaced implementation did. It also pins the label hash: RFC 7518 §4.3 defines no label for RSA-OAEP, so lHash is the digest of the empty octet string (`da39a3ee5e6b4b0d3255bfef95601890afd80709` for SHA-1).

## RFC 4648 §10 — Base64 (adapted to Base64URL, no padding)

`"" → ""`, `f → Zg`, `fo → Zm8`, `foo → Zm9v`, `foob → Zm9vYg`, `fooba → Zm9vYmE`, `foobar → Zm9vYmFy`. High-byte case: `fbffbf → -_-_`.

## RSA-512 arithmetic vector (for `JweBigInt`)

Generated on 2026-09-07 with Python (`random.seed(20260907)`, Miller-Rabin primes). Small enough for `Decimal` arithmetic in a single test, large enough to exercise multi-digit carry. Not a security key.

```text
n  = ae6d141129b984af2852e77ff1e1fd1b837ba94b11685924a12c3b7780d7ab98a3c0eab57d5e00af2c4981e880e219b3c3d2f0dd896ac2ba964e622342a8493b
e  = 10001
d  = a5f923442598e339acbc1e8eaf8263ceff70f7297839fbc110203fc1b9f6fecedd817db8709d9b8d46d2874f8d2958eeaf3e3b48ebe02e62a1066990e6bbba81
p  = ba492733ccc1dbe73542d01469285f7130692184e927139838f9a6e1eda1ea7b
q  = efb3b9f55695910ac531dd17954b2af75d7297bee57f3a5b3c406dde3cb74041
dp = 7cdcfbc1e4c52c38d5a26b06c355a463a22755a858ff304b2025768e8951b671
dq = 6abbbeac0df7df73ca46dfc9e682680969a4e308efabed523ecbf9a021acff81
qi = b193310124618fbe7dd622a6bee42da1d4c837c4e6b2c0cdb65cfb9fde4ad9cc
m  = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
c  = m^e mod n = a0864bdbd09b2040c756bab4d2006148b1ff7f3e0b947f22f24008ca028951dfb8fe387c80ea16b19c8825a24af8149cb8bb0c3f2896eddd10683c6c4faf43ce
k  = 64 octets
```

Small `modPow` checks: `4^13 mod 497 = 445`, `2^1000 mod 1000000007 = 688423210`.

## Interop tokens

All six tokens live in `JweTestKeys` and `JweTestTokens` and are asserted by `JweTest`. Four were generated by `scripts/generate-interop-vectors.mjs` (jose 6.2.3, Node 24) with the throwaway RSA-2048 test key and the pre-shared `dir` key; the two earlier ones were produced with the Node `crypto` module. Two independent producers of the same wire format is a stronger statement than one, which is why the older pair was kept when the implementation that carried it was deleted.

| Token                                          | alg          | enc           |
| ---------------------------------------------- | ------------ | ------------- |
| `RSA_OAEP_256_A256CBC_HS512_TOKEN`             | RSA-OAEP-256 | A256CBC-HS512 |
| `RSA_OAEP_A128CBC_HS256_TOKEN`                 | RSA-OAEP     | A128CBC-HS256 |
| `RSA_OAEP_256_A128CBC_HS256_TOKEN`             | RSA-OAEP-256 | A128CBC-HS256 |
| `DIR_A128CBC_HS256_TOKEN`                      | dir          | A128CBC-HS256 |
| `DIR_A256CBC_HS512_TOKEN` (Node `crypto`)      | dir          | A256CBC-HS512 |
| `RSA_OAEP_A256CBC_HS512_TOKEN` (Node `crypto`) | RSA-OAEP     | A256CBC-HS512 |
