# The VeilCore Record Format

**A specification for evidence of prior possession of genetic material**

Version 0.1 - August 2026

---

## Status of this document

This is a draft specification, published for comment. It describes a record format and a verification procedure. It is not a description of a product.

**The format is open.** Anyone may implement it. There is no licence fee, no certification requirement, and no dependency on any company for the format to function. Three independent implementations - in TypeScript, Python and Rust - pass the same conformance vectors. Each was written from this document rather than translated from the others, which is the evidence that it is unambiguous enough to implement without consulting its authors.

**Verification is free and requires no account, permanently.** This is a design constraint rather than a pricing decision: a record whose verification can be withheld is not evidence.

---

## 1 - What problem this solves

A person who holds genetic material - a plant variety, a breeding line, a cell culture - may later need to establish three things: that they held it; from a date preceding someone else's acquisition of it; and that material in another party's possession descends from theirs.

These are historical claims, ordinarily supported by the holder's own records - which is the weakest available evidence: records produced by the party relying on them, creatable after the fact.

The obvious remedies fail in specific ways.

**Depositing a physical specimen** fixes the date but requires storage. For asexually reproduced material, long-term storage and recovery are frequently infeasible - the reason USDA's Plant Variety Protection Office exempts such varieties from its deposit requirement.

**Notarising a description** fixes the date but requires disclosing the description to a third party. Where the material is valuable and unprotected, that is the one thing the holder cannot afford. It also does not scale: a breeding programme makes hundreds of selections annually, most never registered, any of which might later need defending.

**Registering with a central authority** requires an authority to exist, to be trusted by every party to a future dispute, and to still exist when the dispute arises. Rights in plant material run twenty-five to thirty years.

**And a mandate does not by itself produce evidence.** In December 2025 a US court found California's cannabis seed-to-sale tracking system non-compliant with its enabling statute because its reports were effectively useless in evidence - the system recorded claims that still required human interpretation. Universal mandate, RFID on every plant, and no usable evidence at the end.

This specification describes a form of record that fixes a date without storage, without disclosure, without a trusted authority, and which produces an answer rather than a document to be interpreted.

---

## 2 - How it works, in five sentences

The holder writes down what they possess, in a defined structure. That description is hashed on the holder's own equipment, together with a random value, producing a **commitment** - a 32-byte number which reveals nothing about the description and which could not have been produced from a different description. Only the commitment is published; the description never leaves the holder's possession. Later, to prove what they held, the holder produces the description and any party can recompute the commitment and compare it to the published one. If the two match, the description is the one that existed when the commitment was published.

---

## 3 - The record

A record has three layers. This separation is what allows the format to be used outside its authors' domain without modification.

**The envelope** is domain-blind. No field in it names a crop, an animal, a plant part, or any subject-specific concept. The test for any proposed envelope field is whether an ornamental propagator, a livestock herd book, and a microbial culture collection would all need it.

**The profile** carries the subject fields. A profile is identified by a versioned string and defined by a JSON schema its publisher maintains. The cannabis profile is one profile; a body working with fruit varieties or livestock defines its own and reuses everything else.

**The disclosure vocabulary** names what a holder may grant to a recipient, so that holder, recipient and any adjudicator describe the same disclosure in the same words.

### 3.1 Envelope fields

Required: `formatVersion`, `recordId`, `subjectType`, `profile`, `commitment`, `commitmentAlgorithm`, `anchor`, `sealedAt`, `holder`, `profileData`.

Optional: `attestations`, `parents`, `terms`, `supersedes`, `jurisdictionBindings`, `extensions`.

`subjectType` is one of `plant-genetic-material`, `animal-genetic-material`, `plant-variety`, `other`. `sealedAt` is RFC 3339, UTC, second precision. `extensions` keys must be reverse-DNS.

### 3.2 The anchor

Fields: `chain`, `network`, and optionally `contractAddress`, `txHash`, `blockHeight`, `anchoredAt`, `commitmentAlgorithm`.

`network` may be `undeployed`, which is the correct and honest value for a record sealed locally and never anchored. A verifier treats an undeployed anchor as an unanchored record - the commitment still proves the description is unaltered, but nothing establishes when it was made.

**The anchor is not covered by the commitment.** It is a statement about the commitment and cannot be inside it. This also permits the same record commitment to be anchored in more than one place.

### 3.3 Attestations

An attestation is a third party's statement about the subject: a laboratory report, an inspection, a confirmation of receipt. Fields: `attestationId`, `type`, `attester`, `documentHash`, `hashAlgorithm`, `issuedAt`, and optionally `signature`, `signatureAlgorithm`, `retractedBy`.

**The document itself never enters the record.** Only its hash. A laboratory retains its report and produces it if required; the hash establishes that a produced document is the one that was attested to.

**An attestation should be signed by its attester** (section 7). An unsigned attestation is a claim the registry makes about a party, not a statement by that party, and carries correspondingly less weight.

### 3.4 Parents

Fields: `parentRecordId`, `parentCommitment`, `role`, `declaredBy`, `verified`, `name`.

`parentCommitment` binds to content rather than to an identifier, so a renamed or re-registered parent still resolves. `role` uses the profile's vocabulary - a plant profile may define seed-parent; a livestock profile may define sire.

`declaredBy` distinguishes a holder's own assertion of descent from one confirmed by an attester. These are different evidence and must not be conflated.

---

## 4 - The commitment

### 4.1 Algorithm

The commitment is SHA-256 over the canonical serialisation of the committed fields, expressed as lowercase hexadecimal. The algorithm identifier is `sha256/canonical-json/v1`.

**This deliberately requires no distributed ledger, no specialised runtime, and no dependency on any particular software.** Any implementation, in any language, with a SHA-256 function, can compute and verify a commitment. This is the property that permits a registry the authors do not operate to issue records in this format.

Binding a commitment to a ledger is a separate operation described by the anchor's own algorithm identifier, and only that operation is chain-specific.

### 4.2 Committed fields

The commitment covers `formatVersion`, `recordId`, `subjectType`, `profile`, `commitmentAlgorithm`, `sealedAt`, `holder`, `attestations`, `parents`, `profileData`, and `supersedes`, `jurisdictionBindings`, `extensions` where present.

It does **not** cover `anchor` (a statement about the commitment) or `terms` (issued and revoked after sealing).

### 4.3 The nonce

`profileData` must contain a `nonce`: at least 32 bytes of random data, hex-encoded, generated when the record is sealed.

**Without it the commitment is binding but not hiding.** Fields such as a variety name, a breeder name and a date are guessable. An observer could compute candidate commitments and confirm a guess against a published one. The nonce makes that infeasible.

The nonce must be retained. A commitment cannot be recomputed without it, and a record whose commitment cannot be recomputed cannot be verified by anyone, including its holder.

### 4.4 Canonical serialisation

A commitment is worthless if two implementations serialise the same record differently. These rules are the contract between implementations.

1. **UTF-8**, normalised to **Unicode NFC**.
2. **Object keys sorted** by Unicode code point.
3. **No insignificant whitespace.**
4. **Absent optional fields are omitted**, never serialised as null. An omitted field and a null field must not produce different commitments for the same record.
5. **Array order is preserved and never sorted.** Parent order is meaningful in some domains.
6. **Timestamps** in RFC 3339, UTC, Z suffix, second precision.
7. **Strings** escaped per JSON. **Numbers** in JSON's own form; non-finite values are invalid.

Rule 1 is easy to overlook and produces a failure invisible to a human reader: an accented character composed as a single code point and the same character composed as a base letter plus a combining accent are visually identical and hash differently.

---

## 5 - Anchoring, and batching

Anchoring publishes a commitment to a public ledger so its date is established independently of the holder.

**Commitments are aggregated before anchoring.** They are placed in a Merkle tree and only the root is published, so a single ledger transaction covers many records. Each holder retains an **inclusion proof**: the path from their commitment to the root, plus a reference to the transaction.

This matters for two reasons beyond cost. **The holder needs no ledger account**, no cryptocurrency, and no technical knowledge - the operation happens inside whatever software they already use. And **the per-record cost approaches zero**, which makes it practical to anchor every selection a programme makes rather than only those expected to matter.

The pattern is established rather than novel; it underlies certificate transparency, and OpenTimestamps has used it for over a billion documents.

### 5.1 Inclusion proof

An inclusion proof carries the commitment, a path of sibling hashes with a direction flag on each, the root, a batch identifier, a sealing time, and optionally the anchor.

Verification folds the path from the commitment to the root and compares with the stated root. This requires no network access. Whether that root was anchored, and when, is a separate lookup against the chain - deliberately separate, so that a proof can be checked offline.

Leaf and interior nodes are domain-separated: leaves are hashed with prefix 00, interior nodes with 01. An odd node at any level is **promoted, not duplicated** - duplication permits two different leaf sets to produce the same root.

### 5.2 Pending and anchored

A proof without an anchor is **pending**: the record is in a sealed batch whose root has not yet been published. This is a real state and must be reported as such rather than presented as anchored. It upgrades when the root is anchored; nothing about the record changes.

---

## 6 - Corrections

**Records are never edited and never voided.** A correction issues a new record superseding the old, and both remain. A record that can be quietly altered is not evidence, and voiding is alteration under another name.

A supersedes block carries: the superseded record identifier, a reason, a descent severity, a terms severity, an effective time, who corrected it, and the names of the changed fields.

### 6.1 Severity is classified, not chosen

**Severity is determined by which field changed. It is never selected by the party making the correction.** If the holder chooses, every correction is cosmetic - nobody flags their own correction as the kind that invalidates their downstream agreements.

### 6.2 Two severities, not one

A single flag forces a wrong answer. A variety name change is **cosmetic for descent** - the material did not change - and **material for terms**, because the name may be the licensed thing.

Both flags are reported. A party relying on descent reads one; a party relying on terms reads the other.

Material for both: `parents`, `attestations`, `sealedAt`, `holder`, `subjectType`, `profile`.

Cosmetic for descent, material for terms: `cultivarName` (or the profile equivalent), `breederName`, `claimedCreationDate`.

Material for descent, cosmetic for terms: `breedingMethod`.

Cosmetic for both: `notes`, `internalReference`, `phenotypeSelection`.

**Anything not classified is material for both.** The default is deliberate: an unrecognised change is not assumed harmless.

**A profile publisher may extend this table for its own fields, but may not reclassify an envelope field.** This table is the part of the specification most in need of review by people who adjudicate disputes in a given domain, and it should be expected to change.

### 6.3 What a correction discloses

The changed-fields list names the fields that changed, not their values. A downstream party learns what kind of change occurred without learning the contents of a record they were never granted.

---

## 7 - Attester identity

An attestation is worth what its attester is worth, and that requires knowing who they are. This follows the W3C Verifiable Credentials model, which is the settled answer to this problem.

**The attester holds a keypair and signs.** The signature - not the name - is what binds the statement to a party. Ed25519 over the canonical serialisation of the attestation, excluding the signature fields.

**A trust registry maps a public key to a claimed identity.** Any party may operate one. A registry records what an attester claims about themselves, including any external accreditation and who issued it.

**A registry must not vouch.** It records that a named accreditor accredited the attester, and a verifier decides whether that accreditor means anything to them. A body that both defines an evidence standard and certifies the parties using it has a conflict that a respondent will attack on that ground alone.

Nothing inside a system can establish that a laboratory is a laboratory. That comes from outside - for testing laboratories, ISO/IEC 17025 accreditation is the existing anchor. The registry's role is to record which external authority vouched, in a form a verifier can check independently.

### 7.1 Retraction

An attester may retract an attestation they issued. A retraction is signed by the same key and verified against the attestation it retracts, so that a holder cannot suppress a retraction of an attestation about their own record, and a third party cannot retract someone else's work.

**The attestation is not deleted.** It happened. A retraction is a further entry, and reporting an attestation as retracted is different from reporting that it never existed.

**Retraction is a registry entry rather than a key operation**, so an attester who loses their key can no longer sign new attestations but does not strand the ones they already made.

### 7.2 Reported strength

An attestation is reported as `unsigned` (recorded but not signed - a claim about a party, not a statement by one), `signed` (the signature verifies; the same party issued it, though who that party is remains unestablished), or `signed-and-accredited` (signed, and the attester's registry entry names an external accreditor).

**Strength is reported, never enforced.** A verifier decides what is sufficient for their purpose. A registry that ruled on this would be substituting its judgement for theirs.

---

## 8 - Selective disclosure

A holder grants specific facts to specific recipients. Grants are named for **what the recipient learns**, not for the field revealed - so that the vocabulary is reusable by a registry with a different schema.

`existence` - a sealed record exists, held by this party, from this date.
`integrity` - the record is unaltered since sealing.
`attestation-status` - whether a second party has attested, and at what strength.
`attester-identity` - who the attester is.
`subject-name` - the name of the subject.
`holder-identity` - who the holder is.
`descent-clean` - free of unmet obligations through declared ancestry.
`lineage-depth-n` - descent is established to depth n.
`terms-existence` - terms exist, and their status.
`terms-full` - the terms themselves.

**Ungranted facts are absent from the disclosure, not concealed within it.** A recipient must not be able to recover an ungranted fact by inspecting what they were given.

---

## 9 - Verification

### 9.1 What a verifier can establish without any network access

**That the record is unaltered.** Recompute the commitment from the committed fields per section 4 and compare. A match establishes that the record is exactly as it was when sealed.

**That an inclusion proof is internally consistent.** Fold the path per section 5.1 and compare with the stated root.

**That an attestation is authentic.** Verify the signature against the attester's public key per section 7.

### 9.2 What requires a lookup

**When the record was sealed.** Retrieve the anchoring transaction named in the proof and confirm the root it published matches the proof's root. The transaction's timestamp is the date the commitment demonstrably existed.

**Who the attester is.** Query the trust registry named in the attestation.

**Whether an attestation has been retracted.** Query the registry.

### 9.3 What verification does not establish

Stated plainly, because a claim that overreaches is worse than no claim.

**It does not establish that the record is true.** A commitment proves that a description existed on a date and is unaltered. It does not establish that the description is accurate. Accuracy comes from attestations by parties with something to lose.

**It does not identify material physically.** Whether a specimen is the subject described requires comparison of characteristics or genetic analysis. What the record establishes is that the description, and any analysis attached to it, existed before the dispute - which is what makes a later comparison meaningful rather than circular.

**It does not establish that anything still exists.** Inspection is the only answer to that.

**It does not create any right.** It supports claims made under rights that exist independently.

---

## 10 - Conformance

An implementation is conformant if it reproduces the published test vectors exactly.

Vectors cover canonicalisation - key ordering, omitted versus null, array order preservation, NFC normalisation, nested sorting, numeric and boolean forms - and commitment computation across a range of record shapes, including the requirement that changing the anchor does not change the commitment.

**Conformance is demonstrated, not asserted.** The vector set and a runner are published with the reference implementation. The runner communicates with an implementation over standard input and output, so implementations in any language can be tested.

A deliberately non-conformant implementation is published alongside them, so that the suite can be shown to detect failure rather than merely to pass.

---

## 11 - Design constraints

Recorded because they explain choices that would otherwise look arbitrary, and because an implementer should know which properties may not be traded away.

**Verification is free and requires no account, permanently.** A record whose verification can be withheld is not evidence. Fees may attach to creating a record; never to checking one.

**The format itself is free to implement, permanently.** There is no licence fee for using this specification and no permission required. Certification that an implementation is conformant is a separate service, offered by the authors and by anyone else who cares to offer it; the conformance vectors are published, so any party can test any implementation without asking. A format that charges for its own use does not become infrastructure.

**The subject never leaves the holder.** Only commitments and document hashes are published.

**No party is vouched for by the format.** The format records who vouched. Verifiers decide.

**Nothing is deleted.** Corrections supersede, retractions annotate, and history is preserved.

**Chain-specific operations are confined to anchoring.** Everything else must be computable with a SHA-256 function and nothing more.

**Where a claim cannot be supported, it is stated as unsupported.** A pending anchor is reported as pending; an unsigned attestation is reported as unsigned.

---

## 12 - What is not yet specified

Named so that implementers do not mistake absence for oversight.

**Third-party challenge.** A party other than the holder or an attester contesting a record. The design depends on challenger identity and on a challenge changing what is reported rather than altering the record.

**Payment instruction in terms.** Where terms carry an obligation, how a settlement instruction is expressed. The obligation is recorded; performance is not.

**Cross-registry resolution.** How a verifier locates the registry holding a record given only its identifier.

**Profile governance.** How a profile is registered, versioned, and deprecated, and by whom.

---

## 13 - Comment

This document is published for comment, and specific correction is more useful than general agreement. The classification table in section 6.2 is the part most in need of review by people who adjudicate disputes in a given domain; the authors' assignments there are reasoned but not authoritative.

**Implementations:** TypeScript (reference, published under Apache 2.0 with the conformance vectors), Python, and Rust. All three pass the same vectors.

**Contact:** Hunter Roberts, VeilCore - hunterfrancisroberts@gmail.com

---

*This specification describes a format, not a service. Every property it claims is either demonstrable from the published implementations and vectors, or is stated as a limitation. Where the authors have made a judgement rather than followed a constraint - the field classification in section 6.2 above all - that is marked as such.*
