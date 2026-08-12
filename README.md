# veilcore-records

**[Read the specification](SPEC.md)** — record structure, canonical serialisation, the commitment
procedure, anchoring, corrections, attester identity, and verification. Written for implementers
rather than users of this package.

Build, commit and verify VeilCore records. **No chain dependency** — this package plus a
JavaScript runtime is everything you need.

That is deliberate. A record's commitment is plain SHA-256 over a canonical
serialisation, so any implementation in any language can reproduce it. Anchoring a
commitment to a chain is a separate step, and only that step is chain-specific.

## Verify a record

```js
import { verifyCommitment } from 'veilcore-records';

const result = await verifyCommitment(record);
// { valid: true, computed: '33aaa590...' }
```

Verification proves the record is unaltered since sealing. It does **not** prove the
contents are true — that is answered by attestations and by the anchor's timestamp.

## The record shape

Three layers. The **envelope** is domain-blind: no field in it names a crop, an animal,
or a cannabis concept. The **profile** carries the subject fields. The **disclosure
vocabulary** names what a holder can grant.

The test for any proposed envelope field: would a Dutch orchid propagator or a wagyu
herd book need this too?

## Canonical serialisation

A commitment is worthless if two implementations hash the same record differently.

- Committed fields only. `anchor` and `terms` are excluded by definition
- UTF-8, NFC normalised
- Object keys sorted by Unicode code point
- Absent optional fields omitted, never serialised as null
- Array order preserved, never sorted — parent order is meaningful in some domains
- Timestamps RFC 3339, UTC, second precision

## Defining a profile for another domain

Write a JSON schema listing your fields, publish it, reference it in `profile`. No code,
no permission needed.

Apache-2.0
