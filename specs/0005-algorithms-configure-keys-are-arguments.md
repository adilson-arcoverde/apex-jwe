# 0005: Algorithms are configuration, keys are arguments

- Status: Accepted
- Date: 2026-09-07
- Deciders: the author

## Context

The first version of the facade took both the header and the key in its constructor, and the
documentation recommended keeping a private key in protected custom metadata.

The recommendation is sound, but a library published for other people to use has no business
implying where their keys live. Some will read them from protected custom metadata, some from a
named credential, some from a key service over a callout, some from a test constant. Every one
of those is the caller's decision.

## Decision

`encrypt` and `decrypt` take the key as an argument. The constructor takes only the header.

```apex
Jwe jwe = new Jwe(new JweHeader('RSA-OAEP-256', 'A256CBC-HS512'));
String token = jwe.encrypt(payload, JweKey.fromJson(publicJwk));
String back  = jwe.decrypt(token, JweKey.fromJson(privateJwk));
```

The header stays in the constructor because it is configuration. A recipient decides in advance
which algorithms it will accept, and that decision is what gives pinning its meaning
(see [0004](0004-uniform-failure-for-received-tokens.md)). The key belongs to the message.

## Consequences

- One configured instance serves many recipients and many keys, which matters for key rotation
  and for a transaction that speaks to more than one counterparty.
- No instance holds key material between calls.
- `dir` needs a key object like every other algorithm, so the `Jwe.direct` factory was dropped.
  A shared symmetric key already has a form in JOSE: a JWK with `kty` of `oct`, whose `k` member
  carries the octets (RFC 7518 §6.4). `JweKey` reads those, and `JweKey.fromSecretHex` is a
  shortcut for the hex form a pre-shared secret usually arrives in.
- `JweKey` therefore holds two kinds of key. Asking an RSA key for its secret octets, or a
  symmetric key for its modulus, fails with a message that says which kind it is.
- A key of the wrong kind for the configured algorithm is refused before anything is encrypted,
  with a message that says what to build instead.
