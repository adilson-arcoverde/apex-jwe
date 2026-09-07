# Decision records

Why this library is built the way it is. One record per decision, numbered. Records are not
rewritten: when a decision is replaced, a new record supersedes it and says so, because the
reasoning that was dropped is usually worth as much as the reasoning that stayed.

| #                                                       | Decision                                                         | Status   |
| ------------------------------------------------------- | ---------------------------------------------------------------- | -------- |
| [0001](0001-rewrite-with-behavior-frozen-first.md)      | Rewrite the inherited implementation, with behavior frozen first | Accepted |
| [0002](0002-big-integer-arithmetic-on-decimal.md)       | Run the RSA arithmetic on `Decimal`                              | Accepted |
| [0003](0003-supported-algorithm-matrix.md)              | Support three content encryptions and two key wraps, and no more | Accepted |
| [0004](0004-uniform-failure-for-received-tokens.md)     | One failure message for anything a token controls                | Accepted |
| [0005](0005-algorithms-configure-keys-are-arguments.md) | Algorithms are configuration, keys are arguments                 | Accepted |
| [0006](0006-prefix-every-type.md)                       | Prefix every type with `Jwe`                                     | Accepted |
| [0007](0007-freeze-behavior-with-external-vectors.md)   | Prove the wire format with vectors this project did not produce  | Accepted |
| [0008](0008-apache-2-0.md)                              | Publish under Apache 2.0 rather than a noncommercial license     | Accepted |

## How these records were written

The decisions are the author's. The drafting, the code, the comparisons against published work
and the checking of the claims were done with an AI assistant, in a working session in September 2026. It is said here once, rather than as a banner on top of every record.

Two claims changed under that checking, and both are worth knowing about. Record 0003 had
asserted that Apex has no AES-192, inherited from an earlier design note and never executed
against an org. It is false, so `A192CBC-HS384` is supported and the RFC 7518 Appendix B.2
vector is a round trip test rather than an excuse. And the credits in the README claimed this
code was written independently of the public Apex RSA work it cites, which was not true of its
arithmetic layer. Both corrections are recorded where the mistake was, not quietly patched.

Three documents in this repository answer different questions, and it helps to know which one
to open. `docs/REFACTOR-DESIGN.md` is the plan that was executed: the type map, the eight steps,
and a log of the deviations decided along the way. `docs/ARCHITECTURE.md` describes how the
pieces fit together at rest. These records say why, and are the place to look when a decision
seems wrong.
