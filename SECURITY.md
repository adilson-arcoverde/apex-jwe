# Security policy

## Reporting a vulnerability

Use GitHub's private reporting, which is enabled on this repository: open the
[Security tab](https://github.com/adilson-arcoverde/apex-jwe/security/advisories/new) and
report a vulnerability. The report stays private between you and the maintainer until there is
a fix to publish.

Please do not open a public issue for a vulnerability. An issue describing how to break a
cryptographic library is a working exploit for everyone who deployed it, and Apex libraries are
deployed by copying source into an org, so there is no automatic update to race.

What helps in a report: the algorithms involved, a token or key that shows the problem if one
exists, and what an attacker gets out of it. A test that fails is the clearest form of all.

This is a personal project maintained alongside other work, so there is no response time
commitment. Reports are read, and the ones that hold up get a fix and a credit unless you ask
otherwise.

## What is in scope

The behavior of this library: how it pads, wraps, unwraps, authenticates and rejects. That
includes anything that lets a chosen token reveal more than whether it was accepted, anything
that produces a token a correct implementation would refuse, and anything that accepts a token a
correct implementation would reject.

Also in scope: the arithmetic. A defect in modular exponentiation or in the CRT path can leak
key material, and `JweBigInt` exists as a separate type partly so it can be attacked on its own.

## What is out of scope

Where the caller keeps a private key. `encrypt` and `decrypt` take a `JweKey` and have no
opinion on its storage, so a key readable by the wrong profile is a configuration problem in
the org that deployed it.

The platform primitives underneath: `Crypto`, `EncodingUtil` and the `Decimal` type. A defect
there belongs to Salesforce, and reporting it to them is more useful. Say so in a report if you
believe that is where the problem is, because the boundary is not always obvious from the
outside.

Governor limits as a denial of service. An RSA-2048 unwrap costs 150 to 180 ms of CPU by
construction, and a caller that accepts unlimited tokens per transaction will hit the limit.
That cost is documented in the README and in
[specs/0002](specs/0002-big-integer-arithmetic-on-decimal.md), and the answer is a queueable per
token rather than a change in the library.

## Known limitations

These are documented rather than fixed, because Apex does not offer the tools to fix them.

The padding checks inside EME-OAEP decoding are not constant time, and cannot be made constant
time in Apex. One decoding failure is therefore distinguishable from another by timing. What
removes the value of that distinction is the substitution of RFC 7516 section 11.5: a wrapped key
that fails to unwrap is replaced by random bytes, so every failure lands on the authentication
tag and reports the same message. The reasoning is in
[specs/0004](specs/0004-uniform-failure-for-received-tokens.md).

`RSA-OAEP` uses SHA-1, which JOSE fixes for that algorithm. It is offered because tokens in the
field use it. New integrations should pin `RSA-OAEP-256`.

The test suite ships throwaway RSA key pairs and a pre-shared AES key, as test suites for
cryptographic libraries do. They protect nothing, they are listed in
[docs/TEST-VECTORS.md](docs/TEST-VECTORS.md), and `.gitleaks.toml` allows them so that a secret
scan of this repository comes back clean. Do not copy them into anything.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.0   | Yes       |

The library is ten Apex classes installed as source, so a fix reaches an org when someone
deploys it. There is no supported older release to backport to.
