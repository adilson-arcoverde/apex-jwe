# 0001: Rewrite the inherited implementation, with behavior frozen first

- Status: Accepted
- Date: 2026-09-07
- Deciders: the author

## Context

This library did not start here. It grew inside a client integration in 2021, as four classes
that worked and were maintained under delivery pressure. Hex strings carried values between
methods. The key management algorithm was resolved by name through `Type.forName`. The content
encryption was inlined into the token assembly. The tests covered the code well while pinning
almost nothing that an outside party could verify.

Publishing it unchanged was unattractive, and so was starting from an empty file. The original
had been interoperating with a real counterparty for years, and a rewrite cannot reproduce that
on its own.

## Decision

Rewrite it, but treat the existing behavior as the specification and prove it before changing
anything.

The work was cut into eight steps, each ending with the whole suite green on a validation org.
Step one added no production code: it brought in test vectors, including tokens produced by an
external JOSE library, so every later step had a fixed reference. The original classes stayed in
place and under test throughout, and were deleted only after tokens crossed between the old and
new implementations in both directions.

## Consequences

- Every commit is independently green, and each one names what it proves.
- The crossing tests could not outlive the code they crossed with. They ran before the deletion
  and remain in the history at that commit.
- The wire format never moved. Six tokens produced outside Apex still decrypt to their published
  payloads, and did so at every step.
- Restating every decision turned up three defects in the original: a header built by string
  replacement that a key identifier could inject into, algorithm pinning that compared strings
  case insensitively, and `crit` and `zip` accepted and then ignored. Each is documented where
  it was fixed.
