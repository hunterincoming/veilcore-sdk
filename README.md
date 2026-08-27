# veilcore-records

A breeder cannot prove a variety is theirs without showing the genetics. An examiner
cannot confirm a test was run without taking custody of data they would rather not hold.
A laboratory cannot demonstrate chain of custody without exposing its client list. In
each case the party holding the evidence has to overshare or establish nothing.

This is an open record format for material whose value is bound up in what must stay
private. You prove what you held and when, and prove a specific claim about it, without
handing over the underlying data.

**Verification requires SHA-256 and nothing from us.** No account, no service, no
permission, no fee. A record outlives the party that issued it, the registry that
listed it, and this package.

---

## Check a record

```
npx veilcore-records verify record.json
```

Reports whether the commitment holds, what the attestations establish, and what the
anchor does and does not date. Exit status is 0 when the answer is yes, 1 when it is no.
`seal`, `diff`, `canonical` and `inclusion` are the other commands.

The people who need to check a record are examiners, control officials and analysts.
Asking them to write a script is asking them not to check.

From code:

```js
import { verifyCommitment } from 'veilcore-records';

const result = await verifyCommitment(record);
// { valid: true, computed: '33aaa590...' }
```

Verification proves the record is unaltered since sealing. It does **not** prove the
contents are true — that is what attestations and the anchor's date are for. The format
is careful about this distinction throughout, because a format that blurs it is worth
less than no format at all.

---

## Where to go next

**[Integrating VeilCore](INTEGRATING.md)** — start here if you are adding this to
existing software. A laboratory keeps its own system and adds a commitment to records it
already creates.

**[Records in evidence](EVIDENCE.md)** — for counsel. What a party can establish, how it
is authenticated across jurisdictions, and what it does not prove.

**[The specification](SPEC.md)** — record structure, canonical serialisation, the
commitment procedure, anchoring, corrections, attester identity, verification. Written
for implementers rather than users of this package.

Worked examples in `examples/`: adding commitments to a laboratory's existing intake
process, an Additional Certification Requirement end to end, and establishing
distinctness between two varieties.

---

## Why this is implementable by someone else

A commitment is plain SHA-256 over a canonical serialisation, so any implementation in
any language reproduces it. Anchoring to a chain is a separate step, and only that step
is chain-specific.

Three independent implementations pass the same conformance vectors: this package
(TypeScript), a Python implementation in `conformance/impl.py`, and a Rust
implementation at https://github.com/hunterincoming/veilcore-rs

Section 5 was written from a clean-room test. Given only that section — no code, no
vectors, no conversation — a language model produced a Go implementation that reproduced
every published batch root and folded every published proof, 19 of 19. It inferred path
direction assignment correctly, which the specification never states: it describes how to
fold a path and not how to build one. The gaps that test exposed are now in the text.

The conformance suite ships a deliberately broken implementation, so anyone can confirm
the suite catches failures rather than passing everything.

---

## Canonical serialisation

A commitment is worthless if two implementations hash the same record differently.

- Committed fields only. `anchor` and `terms` are excluded by definition
- UTF-8, NFC normalised
- Object keys sorted by Unicode code point
- Absent optional fields omitted, never serialised as null
- Array order preserved, never sorted — parent order is meaningful in some domains
- Timestamps RFC 3339, UTC, second precision

---

## The record shape

Three layers. The **envelope** is domain-blind: no field in it names a crop, an animal,
or a cannabis concept. The **profile** carries the subject fields. The **disclosure
vocabulary** names what a holder can grant.

The test for any proposed envelope field: would a Dutch orchid propagator, a wagyu herd
book and a microbial culture collection all need it?

### Defining a profile for another domain

Write a JSON schema listing your fields, publish it at a path you control, and name it in
`profile`. There is no registry of profiles, because a registry of profiles is a body
that can refuse one.

Published here: `plant-variety-v1`, `seed-lot-v1` and `cannabis-v0.1`.

---

## Proving a single claim

The commitment above establishes that a whole record is unaltered. Establishing a single
claim — that a sealed figure meets a threshold, that two records differ at k or more
fields — without disclosing the record needs a per-field commitment scheme.

Section 12 of the specification states what specifying one would have to settle, and an
independent implementation of that shape has been exercised against records in this
format. `examples/acr-trait-verification.mjs` and `examples/distinctness.mjs` show what
a certifying body receives and what stays with the holder.

---

## Status

Published for comment. The specification is stable enough to implement against and
specific correction is more useful than general agreement — section 13 says where review
is most needed.

Apache-2.0
