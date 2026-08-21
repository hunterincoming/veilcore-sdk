# The VeilCore Record Format

**A specification for evidence of prior possession of genetic material**

Version 0.1 - August 2026

---

## Status of this document

This is a draft specification, published for comment. It describes a record format and a verification procedure. It is not a description of a product.

**The format is open.** Anyone may implement it. There is no licence fee, no certification requirement, and no dependency on any company for the format to function. Three independent implementations - in TypeScript, Python and Rust - pass the same conformance vectors. Each was written from this document rather than translated from the others, which is the evidence that it is unambiguous enough to implement without consulting its authors. The vectors cover canonicalisation, commitment computation and inclusion proofs; attestations, corrections and resolution are implemented in the reference implementation and are not yet part of the vector set.

**Verification is free and requires no account, permanently.** This is a design constraint rather than a pricing decision: a record whose verification can be withheld is not evidence.

---

## 1 - What problem this solves

A person who holds genetic material - a plant variety, a breeding line, a cell culture - may later need to establish three things: that they held it; from a date preceding someone else's acquisition of it; and that material in another party's possession descends from theirs.

These are historical claims, ordinarily supported by the holder's own records - which is the weakest available evidence: records produced by the party relying on them, creatable after the fact.

The obvious remedies fail in specific ways.

**Depositing a physical specimen** fixes the date but requires storage. For asexually reproduced material, long-term storage and recovery are frequently infeasible - the reason USDA's Plant Variety Protection Office exempts such varieties from its deposit requirement.

**Notarising a description** fixes the date but requires disclosing the description to a third party. Where the material is valuable and unprotected, that is the one thing the holder cannot afford. It also does not scale: a breeding programme makes hundreds of selections annually, most never registered, any of which might later need defending.

**Registering with a central authority** requires an authority to exist, to be trusted by every party to a future dispute, and to still exist when the dispute arises. Rights in plant material run twenty-five to thirty years.

**And a mandate does not by itself produce evidence.** In December 2025 a US court found California's cannabis track-and-trace system non-compliant with its enabling statute. The statute requires the database to be designed to flag irregularities for investigation; the court held that generating large volumes of reports and raw transaction data does not satisfy it, because nothing identifies irregular activity by objective criteria and analysts review manually without an established definition of what an irregularity is. A final judgment in August 2026 gave the department six months to define those criteria. Universal mandate, RFID on every plant, eight years, and a system that records without establishing anything.

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

Optional: `subject`, `identification`, `registrations`, `attestations`, `parents`, `terms`, `supersedes`, `jurisdictionBindings`, `extensions`.

**Three of those carry what every subject has, whatever domain it comes from.** They are in the envelope rather than in a profile because the alternative is every profile redefining them, and definitions that are redefined drift.

`subject` — `name`, `internalDesignation`, `taxon`, `originator`, `claimedCreationDate`. Note `originator` rather than "breeder": a culture collection has a depositor and a herd book has a keeper.

`identification` — `method`, `panel`, `data`, `performedBy`, `performedOn`, `reportHash`. Every domain identifies subjects by something measurable, and the shape is the same everywhere: a named method and values produced by it. What the values mean is the profile's business; that they exist and are committed is the envelope's. This is what lets a holder show marker data to one examiner and prove afterwards that it is what was sealed, without it ever being published.

`registrations` — `authority`, `reference`, `status`, `filedOn`. External rights registrations, recorded and never verified.

**The test for whether a field belongs here rather than in a profile:** would an ornamental propagator, a livestock herd book, and a microbial culture collection all need it? Propagation type fails that test — seed versus vegetative means nothing to a herd book — so it lives in the plant profile.

`subjectType` is one of `plant-genetic-material`, `animal-genetic-material`, `plant-variety`, `other`. `sealedAt` is RFC 3339, UTC, second precision. `extensions` keys shall be reverse-DNS.

### 3.2 The anchor

Fields: `chain`, `network`, and optionally `contractAddress`, `txHash`, `blockHeight`, `anchoredAt`, `commitmentAlgorithm`.

`network` may be `undeployed`, which is the correct and honest value for a record sealed locally and never anchored. A verifier treats an undeployed anchor as an unanchored record - the commitment still proves the description is unaltered, but nothing establishes when it was made.

**The anchor is not covered by the commitment.** It is a statement about the commitment and cannot be inside it.

**A record may carry several anchors**, and `anchor` accepts either a single object or an array. This is what makes the format usable across jurisdictions that recognise different mechanisms, without any jurisdiction-specific rule appearing in the format itself.

| `kind` | What it is | Where it carries most weight |
|---|---|---|
| `ledger` | The commitment, or a batch root containing it, published in a public chain | No general presumption. Italian Law 12/2019 grants blockchain timestamps the effect of an eIDAS timestamp; Chinese Internet Courts have accepted blockchain evidence since 2018; US courts authenticate under FRE 901(b)(9) |
| `rfc3161` | A signed timestamp token from a Time Stamping Authority | Where the TSA is a Qualified Trust Service Provider on an EU trusted list, eIDAS Article 42 attaches a presumption of accuracy, and the burden falls on whoever disputes the date |
| `notarial` | A timestamp applied by a notary or equivalent officer | Follows local rules on notarial acts |

An anchor with no `kind` is `ledger`, so records written before this field existed remain valid.

**Because no anchor is inside the commitment, adding one never invalidates a record.** A holder may obtain a qualified timestamp years after sealing and attach it; the commitment is unchanged and every proof already issued still verifies.

**A registry states what an anchor is. It does not state what a court will do with it.** Where an anchor claims qualified status, that is the issuer's claim, and a verifier confirms it against the relevant trusted list.

### 3.3 Attestations

An attestation is a third party's statement about the subject: a laboratory report, an inspection, a confirmation of receipt. Fields: `attestationId`, `type`, `attester`, `subjectCommitment`, `documentHash`, `hashAlgorithm`, `issuedAt`, and optionally `signature`, `signatureAlgorithm`, `retractedBy`.

**`subjectCommitment` binds the attestation to one record and is required.** It carries the commitment of the record the attestation is about. Without it an attestation is a statement about nothing in particular: a valid signed attestation issued for one record could be copied into another record and would verify there, which would let any party attach a laboratory's genuine signature to material the laboratory never saw. The binding is inside the signed material (section 7), so moving an attestation between records breaks its signature.

**An attestation naming a `subjectCommitment` that does not match the record carrying it is invalid**, and an implementation shall reject the record rather than report the attestation as merely unverified. A mismatch is not a weak claim; it is a claim about a different record.

**The document itself never enters the record.** Only its hash. A laboratory retains its report and produces it if required; the hash establishes that a produced document is the one that was attested to.

**An attestation should be signed by its attester** (section 7). An unsigned attestation is a claim the registry makes about a party, not a statement by that party, and carries correspondingly less weight.

### 3.4 Parents

Fields: `parentRecordId`, `parentCommitment`, `role`, `declaredBy`, `verified`, `name`.

`parentCommitment` binds to content rather than to an identifier, so a renamed or re-registered parent still resolves. `role` uses the profile's vocabulary - a plant profile may define seed-parent; a livestock profile may define sire.

`declaredBy` distinguishes a holder's own assertion of descent from one confirmed by an attester. These are different evidence, and the format does not conflate them.

### 3.5 Terms, and the payment instruction

Terms are issued and revoked after sealing, and are therefore not covered by the commitment (section 4.2). What the terms say can change; what the record says cannot.

Terms may carry a `paymentInstruction` recording what is owed. Fields: `obligationRef`, an issuer-scoped identifier for the obligation this settles; `amount`, a fixed value or a formula, as an opaque string; `unit`, a currency or unit code, recorded and never converted; `payee`, an identifier resolvable by the parties; and optionally `trigger`, the event or date on which the obligation becomes due.

**An implementation shall treat `amount` as opaque** and shall not evaluate or compute with it. A format that computes an amount has taken a position on what is owed.

**An issuer shall not place a financial account identifier in `payee`** - bank account or routing numbers, card numbers, IBANs, or blockchain addresses. An identifier is resolvable by the parties to the agreement; settlement detail in a permanent record is a liability to everyone named in it. This is a requirement on issuers rather than a canonicalisation rule, so it sits outside the conformance vectors of section 10, which establish only that two implementations compute identical commitments. Validation of field content belongs to a separate conformance profile, defined when a body states what it needs to audit.

**A record does not carry a payment instruction.** Records state what is true of a subject; an obligation exists only between parties to an agreement.

The instruction is recorded. Performance is not: nothing in this format moves funds, holds them, or confirms that anyone paid.

---

## 4 - The commitment

### 4.1 Algorithm

The commitment is SHA-256 over the canonical serialisation of the committed fields, expressed as lowercase hexadecimal. The algorithm identifier is `sha256/canonical-json/v1`.

**This deliberately requires no distributed ledger, no specialised runtime, and no dependency on any particular software.** Any implementation, in any language, with a SHA-256 function, can compute and verify a commitment. This is the property that permits a registry the authors do not operate to issue records in this format.

Binding a commitment to a ledger is a separate operation described by the anchor's own algorithm identifier, and only that operation is chain-specific.

### 4.2 Committed fields

The commitment covers, exactly and exhaustively:

`attestations`, `commitmentAlgorithm`, `extensions`, `formatVersion`, `holder`, `identification`, `jurisdictionBindings`, `parents`, `profile`, `profileData`, `recordId`, `registrations`, `sealedAt`, `subject`, `subjectType`, `supersedes`.

**`attestations` and `parents` are always committed**, as an empty array when absent. Every other optional field is committed only when present, and is omitted rather than serialised as null.

The list is exhaustive because a verifier that includes a different set computes a different commitment and reports a genuine record as altered. A field added to this specification without being added to this list is a field two conformant implementations will disagree about.

It does **not** cover `anchor` (a statement about the commitment) or `terms` (issued and revoked after sealing).

**On attestations added after sealing.** Because `attestations` is committed, adding an attestation to a sealed record changes its commitment, which means it is a correction under section 6 and issues a superseding record. This is deliberate. A record whose attestation set can change without changing its commitment is a record whose evidentiary content is mutable, and the superseding record preserves the original alongside it.

### 4.3 The nonce

`profileData` shall contain a `nonce`: at least 32 bytes of random data, hex-encoded, generated when the record is sealed.

**The nonce shall be generated by a cryptographically secure pseudorandom number generator.** `crypto.getRandomValues` in a browser, `crypto.randomBytes` in Node, `secrets` in Python, `getrandom` in Rust. A nonce from a general-purpose random function - `Math.random`, `rand()`, a seeded generator - is predictable to anyone who can observe or guess the seed, and a predictable nonce defeats the property the nonce exists to provide.

**Without it the commitment is binding but not hiding.** Fields such as a variety name, a breeder name and a date are guessable. An observer could compute candidate commitments and confirm a guess against a published one. The nonce makes that infeasible.

**A nonce is never reused across records.** Two records sharing a nonce leak the fact that they were sealed by the same party using the same source, and reduce the work required to attack either.

The nonce shall be retained. A commitment cannot be recomputed without it, and a record whose commitment cannot be recomputed cannot be verified by anyone, including its holder.

### 4.4 Canonical serialisation

A commitment is worthless if two implementations serialise the same record differently. These rules are the contract between implementations.

These rules follow **RFC 8785 (JSON Canonicalization Scheme)** where they overlap with it. Where this specification is stricter, it says so.

1. **UTF-8**, normalised to **Unicode NFC** — **both keys and string values**. Normalise before sorting. If two keys in the same object are equal after normalisation, **the record is invalid**; an implementation shall reject it rather than pick one, because picking one means two implementations pick differently.

2. **Object keys sorted by Unicode code point.** **This is not JavaScript's default sort**, which compares UTF-16 code units and orders characters above U+FFFF incorrectly relative to characters in the range U+E000–U+FFFF. An implementation in JavaScript shall sort by code point explicitly. This is a real divergence, not a theoretical one: `{"｡":1,"😀":2}` orders differently under the two rules.

3. **No insignificant whitespace.**

4. **A null is invalid anywhere in a committed field**, at any nesting depth. Absent optional fields are omitted; a field whose value is null makes the record invalid and an implementation shall reject it. Earlier drafts said an omitted field and a null field must not differ, which is unimplementable without also saying whether a nested null is dropped or serialised — implementations diverged on exactly that. Rejection is the only rule with one reading.

5. **Array order is preserved and never sorted.** Parent order is meaningful in some domains.

6. **Timestamps** in RFC 3339, UTC, `Z` suffix, second precision.

7. **Strings** escaped per RFC 8785 section 3.2.2.2 — the shortest escaping, using the two-character forms where they exist and lowercase `\uXXXX` otherwise.

8. **Numbers** are serialised per RFC 8785 section 3.2.2.3, which is ECMAScript's shortest round-trip representation. `1e-7` serialises as `1e-7`, never `1e-07`. Non-finite values are invalid.

   **A profile may require integers.** Where a value carries a laboratory measurement, a profile publisher should consider requiring it as a string rather than a float: implementations agree on integers within ±2^53 and on strings, and every remaining disagreement about numbers lives in the space between.

Rule 1 is easy to overlook and produces a failure invisible to a human reader: an accented character composed as a single code point and the same character composed as a base letter plus a combining accent are visually identical and hash differently.

---

## 5 - Anchoring, and batching

Anchoring publishes a commitment to a public ledger so its date is established independently of the holder.

**Commitments are aggregated before anchoring.** They are placed in a Merkle tree and only the root is published, so a single ledger transaction covers many records. Each holder retains an **inclusion proof**: the path from their commitment to the root, plus a reference to the transaction.

This matters for two reasons beyond cost. **The holder needs no ledger account**, no cryptocurrency, and no technical knowledge - the operation happens inside whatever software they already use. And **the per-record cost approaches zero**, which makes it practical to anchor every selection a programme makes rather than only those expected to matter.

The pattern is established rather than novel; it underlies certificate transparency, and OpenTimestamps has used it for over a billion documents.

### 5.1 Building a batch

A batch is built from a set of commitments. Every rule here affects the root, so two implementations that differ on any of them will disagree about whether a genuine record is in a batch.

**Commitments are lowercase hexadecimal strings** of 64 characters, as produced by section 4.1.

**Duplicates are removed.** A commitment appearing more than once contributes one leaf. Two identical records are one record; counting them twice would make the root depend on how many times a caller happened to submit the same thing.

**Leaves are sorted in ascending lexicographic order** of the hexadecimal string, compared by code point. Sorting is what makes a root independent of the order commitments arrived in, so two parties assembling the same set get the same root.

**An empty batch is refused.** An implementation shall reject it rather than publish the hash of nothing, which would be a root that proves nothing and to which anything could later be claimed to belong.

### 5.2 Hashing

Two rules, and both are places an implementation will silently diverge if they are not stated exactly.

**Nodes are hashed as ASCII text, not as decoded bytes.** The input to SHA-256 is a string of hexadecimal characters with a two-character prefix, encoded as UTF-8. It is not the prefix byte followed by 32 raw bytes.

**The prefixes are the ASCII characters `0` `0` and `0` `1`**, not the bytes `0x00` and `0x01`.

A leaf:

    hashLeaf(commitment) = SHA256_hex( "00" || commitment )

An interior node:

    hashNode(left, right) = SHA256_hex( "01" || left || right )

where `||` is string concatenation, both operands are 64-character lowercase hex, and `SHA256_hex` returns lowercase hex. So a leaf hashes a 66-character string and an interior node hashes a 130-character string.

Worked example, so an implementation can check itself before running the vectors. For a batch of the single commitment `0000000000000000000000000000000000000000000000000000000000000000`, the input to SHA-256 is the two prefix characters followed by the 64 zeros — 66 characters in total — and the resulting digest is both the leaf hash and, because the batch has one leaf, the batch root.

**Leaves and interior nodes are domain-separated** by those prefixes so that a leaf can never be presented as an interior node, and so that an interior node's preimage cannot be mistaken for a leaf's.

### 5.3 The tree

Starting from the sorted, de-duplicated leaves:

1. Hash each commitment with `hashLeaf` to produce the bottom level.
2. While the level holds more than one node, produce the next level by taking nodes in pairs, left to right, and computing `hashNode(left, right)` for each pair.
3. **If a level holds an odd number of nodes, the last node is carried up to the next level unchanged.** It is *not* hashed again, and it is *not* paired with itself. Duplicating it would let two different leaf sets produce the same root. **A promoted node contributes no step to the paths beneath it.** Nothing was combined at that level, so there is nothing to record.
4. The single remaining node is the batch root.

A batch of one leaf therefore has a root equal to `hashLeaf(commitment)`, and its proof path is empty.

### 5.4 Inclusion proof

An inclusion proof carries the commitment, a path of sibling hashes with a direction flag on each, the root, a batch identifier, a sealing time, and optionally the anchor.

Field names, so that two implementations can exchange a proof:

| Field | Type | Meaning |
|---|---|---|
| `commitment` | hex string | The commitment being proven |
| `path` | array | Ordered from the leaf upward. Empty for a single-leaf batch |
| `path[].sibling` | hex string | The other node at that level |
| `path[].siblingIsLeft` | boolean | **True when the sibling is the left operand** and the node folded so far is the right one |
| `root` | hex string | The root the path folds to |
| `batchId` | string | Issuer-scoped batch identifier |
| `sealedAt` | RFC 3339, UTC, second precision | When the batch was sealed |
| `anchor` | object | Optional, per section 3.2 |

**`siblingIsLeft` describes the sibling, not the node being folded.** The inverse reading is the single most likely divergence in this section, and roughly half of any given proof still verifies under it, which makes the error hard to see.

Verification:

    node = hashLeaf(proof.commitment)
    for each step in proof.path, in order:
        if step.siblingIsLeft:  node = hashNode(step.sibling, node)
        else:                   node = hashNode(node, step.sibling)
    the proof is internally consistent if node equals proof.root

This requires no network access. Whether that root was anchored, and when, is a separate lookup against the chain - deliberately separate, so that a proof can be checked entirely offline.

**A path has a maximum accepted depth of 64.** An implementation shall reject a longer path rather than fold it. 64 levels covers any batch anyone will build, and an unbounded path is an unbounded amount of work handed to a verifier by whoever supplied the proof.

### 5.5 Pending and anchored

A proof without an anchor is **pending**: the record is in a sealed batch whose root has not yet been published. This is a real state and shall be reported as such rather than presented as anchored. It upgrades when the root is anchored; nothing about the record changes.

**A batch root establishes a date no earlier than its anchoring transaction.** Where a batch is sealed well before it is anchored, the interval is not evidence of anything. The date a verifier may rely on is the date the transaction was confirmed, not the batch's own `sealedAt`, which is a claim by whoever assembled the batch.

---

## 6 - Corrections

**Records are never edited and never voided.** A correction issues a new record superseding the old, and both remain. A record that can be quietly altered is not evidence, and voiding is alteration under another name.

A supersedes block carries: the superseded record identifier, a reason, a descent severity, a terms severity, an effective time, who corrected it, and the names of the changed fields.

### 6.1 Severity is classified, not chosen

**Severity is determined by which field changed. It is never selected by the party making the correction.** If the holder chooses, every correction is cosmetic - nobody flags their own correction as the kind that invalidates their downstream agreements.

### 6.2 Two severities, not one

A single flag forces a wrong answer. A variety name change is **cosmetic for descent** - the material did not change - and **material for terms**, because the name may be the licensed thing.

Both flags are reported. A party relying on descent reads one; a party relying on terms reads the other.

Material for both: `parents`, `attestations`, `holder`, `subjectType`, `profile`.

**A correcting record's own identity fields are not changes.** `recordId`, `commitment`, the nonce, `sealedAt` and `anchor` necessarily differ between a record and the record that supersedes it, because the latter is a new record sealed later. Reporting those as changes would make every correction material and the classification worthless. Backdating is prevented by a different property: the superseded record is never altered or deleted, so its own seal time and anchor remain independently checkable.

Cosmetic for descent, material for terms: `cultivarName` (or the profile equivalent), `breederName`, `claimedCreationDate`.

Material for descent, cosmetic for terms: `breedingMethod`.

Cosmetic for both: `notes`, `internalReference`, `phenotypeSelection`.

**Anything not classified is material for both.** The default is deliberate: an unrecognised change is not assumed harmless.

**A supersedes chain shall not contain a cycle**, and an implementation shall reject a record whose supersedes chain returns to a record already seen while walking it. A cycle is either an error or an attempt to make a chain unwalkable.

**A profile publisher may extend this table for its own fields, but may not reclassify an envelope field.** This table is the part of the specification most in need of review by people who adjudicate disputes in a given domain, and it should be expected to change.

### 6.3 What a correction discloses

The changed-fields list names the fields that changed, not their values. A downstream party learns what kind of change occurred without learning the contents of a record they were never granted.

---

## 7 - Attester identity

An attestation is worth what its attester is worth, and that requires knowing who they are. This follows the W3C Verifiable Credentials model, which is the settled answer to this problem.

**The attester holds a keypair and signs.** The signature - not the name - is what binds the statement to a party. Ed25519 over the canonical serialisation of the attestation, excluding the signature fields.

**The signed material includes `subjectCommitment`** (section 3.3). This is what makes a signature a statement about one record rather than a portable credential that verifies anywhere it is pasted.

**A trust registry maps a public key to a claimed identity.** Any party may operate one. A registry records what an attester claims about themselves, including any external accreditation and who issued it.

**A registry shall not vouch.** It records that a named accreditor accredited the attester, and a verifier decides whether that accreditor means anything to them. A body that both defines an evidence standard and certifies the parties using it has a conflict that a respondent will attack on that ground alone.

Nothing inside a system can establish that a laboratory is a laboratory. That comes from outside - for testing laboratories, ISO/IEC 17025 accreditation is the existing anchor. The registry's role is to record which external authority vouched, in a form a verifier can check independently.

### 7.1 Retraction

An attester may retract an attestation they issued. **A retraction is signed by the same key that signed the attestation**, and is verified against the attestation it retracts, so that a holder cannot suppress a retraction of an attestation about their own record, and a third party cannot retract someone else's work.

**A retraction is recorded as a registry entry rather than as an operation on the record or the chain.** The record is not altered; the registry gains an entry that a verifier finds when it queries the attester (section 9.2). These are two separate things and earlier drafts conflated them: the signature is what authorises the retraction, the registry entry is where it lives.

**The attestation is not deleted.** It happened. A retraction is a further entry, and reporting an attestation as retracted is different from reporting that it never existed.

**An attester who has lost their key cannot retract.** This follows from requiring the signature and is stated rather than worked around: a registry that could retract on an attester's behalf is a registry that can retract without them. The mitigation is key rotation before loss, and a registry entry marking a key inactive from a date (section 7.3), which tells a verifier the attester can no longer speak with that key without claiming anything about attestations already made.

### 7.2 Reported strength

An attestation is reported as `unsigned` (recorded but not signed - a claim about a party, not a statement by one), `signed` (the signature verifies; the same party issued it, though who that party is remains unestablished), or `signed-and-accredited` (signed, and the attester's registry entry names an external accreditor).

**Strength is reported, never enforced.** A verifier decides what is sufficient for their purpose. A registry that ruled on this would be substituting its judgement for theirs.

### 7.3 Key rotation, expiry and compromise

Rights in plant material run twenty-five to thirty years. No signing key should be assumed to survive that, and a format that does not say what happens when a key changes hands has left its longest-lived records undefended.

**A registry entry carries a set of keys, each with a validity interval**: `publicKey`, `validFrom`, and optionally `validUntil` and `status`. An attestation verifies against the key that was valid at its `issuedAt`, not against whichever key the attester holds today.

**Rotation is ordinary and does not disturb history.** An attester adds a new key with a `validFrom`, and sets `validUntil` on the old one. Attestations signed under the old key continue to verify as `signed`, because they were signed when that key was the attester's key.

**Compromise is a different statement and is recorded differently.** Where a key is believed compromised, the registry entry marks it `compromised` with a `compromisedFrom` date. A verifier then reports attestations issued under that key on or after that date as **suspect**, and attestations issued before it as `signed`, noting that the key was later compromised.

**A compromise date is a claim by the attester, not a finding.** The registry records who said it and when. Where the date matters to a dispute, the anchoring of the attested record is independent evidence of when the attestation existed, and a verifier weighs the two. As everywhere else in this format, the registry records and does not adjudicate.

**A verifier that cannot reach the registry reports the attestation as `signed` with the attester's identity unestablished**, rather than treating unreachability as either validity or invalidity.

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

**Ungranted facts are absent from the disclosure, not concealed within it.** A recipient shall not be able to recover an ungranted fact by inspecting what they were given.

### 8.1 What `integrity` currently costs

Stated plainly because the alternative is a grant that promises more than the mechanism delivers.

**Recomputing a commitment requires every committed field, including the nonce.** A recipient granted `integrity` under the commitment scheme in section 4 therefore receives the whole committed record. `integrity` is separable from the other grants in the vocabulary, but it is not yet separable in computation: granting it discloses the record.

**A per-field commitment scheme is what makes it separable**, by committing each field as a leaf and sealing a root, so that a holder can demonstrate that a shown value is the sealed one without showing the rest. That scheme is not specified in this document (section 12).

Until it is, an implementation shall not present `integrity` to a holder as a disclosure narrower than full disclosure of the committed fields. A grant that a holder believes is narrow, and is not, is worse than no grant.

---

## 9 - Verification

### 9.1 What a verifier can establish without any network access

**That the record is unaltered.** Recompute the commitment from the committed fields per section 4 and compare. A match establishes that the record is exactly as it was when sealed.

**That an inclusion proof is internally consistent.** Fold the path per section 5.4 and compare with the stated root.

**That an attestation is authentic and belongs to this record.** Verify the signature against the attester's public key per section 7, and confirm that the attestation's `subjectCommitment` is this record's commitment. Both are required; a valid signature on an attestation about a different record establishes nothing about this one.

### 9.2 What requires a lookup

**When the record was sealed.** Retrieve the anchoring transaction named in the proof and confirm the root it published matches the proof's root. The transaction's timestamp is the date the commitment demonstrably existed.

**Who the attester is.** Query the trust registry named in the attestation.

**Whether the signing key was valid at issue, and whether it was later rotated or reported compromised.** Query the registry (section 7.3).

**Whether an attestation has been retracted.** Query the registry.

### 9.3 What verification does not establish

Stated plainly, because a claim that overreaches is worse than no claim.

**It does not establish that the record is true.** A commitment proves that a description existed on a date and is unaltered. It does not establish that the description is accurate. Accuracy comes from attestations by parties with something to lose.

**It does not identify material physically.** Whether a specimen is the subject described requires comparison of characteristics or genetic analysis. What the record establishes is that the description, and any analysis attached to it, existed before the dispute - which is what makes a later comparison meaningful rather than circular.

**It does not establish that anything still exists.** Inspection is the only answer to that.

**It does not create any right.** It supports claims made under rights that exist independently.

---

## 10 - Conformance

**Requirement language.** In this specification **shall** and **shall not** state
requirements, **should** states a recommendation, **may** states permission, and **can**
states a possibility or capability, following ISO/IEC Directives Part 2. Prose that uses
none of those words is explanation and states no requirement. The distinction matters
beyond style: an accreditation body cannot place a document on a laboratory's scope of
accreditation unless its requirements are stated as requirements.

**Requirements fall on two different parties, and only one of them is testable here.**
Most requirements below fall on an implementation, and the vectors test them. A few fall
on an issuer, a holder, a registry or a challenger — that an issuer shall not put an
account identifier in `payee` (section 3.5), that a holder shall retain the nonce (section
4.3), that a registry shall not vouch (section 7), that a challenger shall seal their own
claim first (section 11.7). Those are requirements, and no vector can establish them.
A conformance profile covering party conduct is not defined here (section 12).

An implementation is conformant if it reproduces the published test vectors exactly.

Vectors cover canonicalisation - key ordering, omitted versus null, array order preservation, NFC normalisation, nested sorting, numeric and boolean forms - commitment computation across a range of record shapes, including the requirement that changing the anchor does not change the commitment, and inclusion proofs across batch sizes chosen so that an implementation which duplicates an odd node rather than promoting it will disagree.

**Conformance is demonstrated, not asserted.** The vector set and a runner are published with the reference implementation. The runner communicates with an implementation over standard input and output, so implementations in any language can be tested.

A deliberately non-conformant implementation is published alongside them, so that the suite can be shown to detect failure rather than merely to pass.

**The runner distinguishes a refusal from a failure to run.** An implementation that produces no output fails the rejection vectors rather than passing them. Before August 2026 it did not, and a command that did nothing at all scored full marks on that section - a suite that scores silence as a refusal cannot tell a correct implementation from a missing one.

**What conformance does not cover.** These vectors establish that two implementations compute identical commitments and fold identical proofs for the same inputs. They do not establish that a field's contents are permissible - see section 12.

---

## 11 - Design constraints

Recorded because they explain choices that would otherwise look arbitrary, and because an implementer should know which properties may not be traded away.

**Verification is free and requires no account, permanently.** A record whose verification can be withheld is not evidence. Fees may attach to creating a record; never to checking one.

**The format itself is free to implement, permanently.** There is no licence fee for using this specification and no permission required. Certification that an implementation is conformant is a separate service, offered by the authors and by anyone else who cares to offer it; the conformance vectors are published, so any party can test any implementation without asking. A format that charges for its own use does not become infrastructure.

**The subject never leaves the holder.** Only commitments and document hashes are published.

**No party is vouched for by the format.** The format records who vouched. Verifiers decide.

**Nothing is deleted.** Corrections supersede, retractions annotate, and history is preserved.

**Chain-specific operations are confined to anchoring.** Everything else is computable with a SHA-256 function and nothing more.

**The format records obligations and never performs them.** An amount owed can be expressed in terms; nothing in this format moves funds or confirms that anyone paid.

**A record survives its registry.** Every property a verifier relies on - the commitment, the inclusion proof, the anchor - is checkable from the published package and a chain lookup, with no registry available. Resolution is a convenience; it is never the thing evidence rests on.

**Where a claim cannot be supported, it is stated as unsupported.** A pending anchor is reported as pending; an unsigned attestation is reported as unsigned.

---

## 11.5 - Resolution across registries

If anyone may operate a registry, a verifier holding a record identifier needs to be able to find the one that issued it.

**There is no central directory, and none is planned.** A study of failed persistent-identifier systems found the common cause was reliance on a central authority or infrastructure; even DOI carries this weakness, because prefix allocation sits with a single organisation. A format whose resolution depends on one party has that party as a permanent single point of failure.

**Instead, a registrar identifies itself by a domain it already controls.** A qualified identifier is:

    vc:northfield.example.com/LAB-2026-00417

The authority is a domain name. The local part is whatever the issuer already uses internally, unchanged - which is what keeps adoption cheap.

**Resolution is two requests.** A verifier fetches `https://<authority>/.well-known/veilcore-registry`, which returns a descriptor naming the registry's API, the format versions it issues, and where it anchors. The verifier then asks that API for the record.

Nothing in this path touches infrastructure operated by the authors of this specification, and there is no prefix to allocate, no authority to petition, and no registration step. GS1 resolves barcodes by the same mechanism.

A registry descriptor contains: `name`, `api`, `formatVersions`, optionally `anchors` and `publicKey`.

**An unqualified identifier remains valid within its own registry.** It simply cannot be resolved by a stranger, which is the honest consequence of not naming an authority.

### 11.5.1 What happens when a domain changes hands

Domains lapse. A registry that closes in 2031 leaves its domain to be bought by anyone, who can then serve a descriptor and an API for every identifier that registry ever issued. Over the twenty-five to thirty year life of a plant variety right this is not an edge case, it is the expected end state of most registrars.

**Resolution is not evidence, and nothing in this format treats it as evidence.** A record's commitment, its inclusion proof and its anchor are verifiable from the published package and a chain lookup, with no registry involved (section 9.1). A party who holds their record can prove it after their registrar is gone, which is the property that makes a registrar's failure survivable.

**A verifier should record the registry's `publicKey` at the time a record is received**, and treat a descriptor later served under the same authority with a different key as a different party. A changed key is not proof of anything improper, and is not treated as such; it is a fact a verifier is entitled to see rather than to have silently resolved.

**A registrar's descriptor, however served, is never a substitute for the anchor.** Where a descriptor and an anchored commitment disagree, the anchor governs. A registry cannot alter what was published to a chain, and this is the reason resolution can be allowed to fail without evidence failing with it.

---

## 11.6 - Profiles, and who governs them

A profile defines the subject fields for a domain. The cannabis profile is one; a body working with fruit varieties, ornamentals or livestock defines its own.

**Nobody grants permission to define a profile.** A profile is identified by an authority and a name, resolved the same way a record is:

    veilcore/profile/cannabis/v0.1        published by the authors of this specification
    jp.go.maff/profile/variety/v1         published by whoever controls jp.go.maff

An authority publishes a JSON schema at a path it controls, and any implementation can fetch it. There is no registry of profiles, because a registry of profiles is a body that can refuse one.

**A profile publisher decides its own versioning.** Version identifiers are opaque to the envelope; a record names a profile and an implementation either recognises it or does not. Two records naming different profile versions are different records, not the same record read differently.

**A profile schema is fetched to validate, never to verify.** A commitment is computed from the record's own fields and never from a schema, so a profile that becomes unreachable, or is altered by its publisher, cannot change what any record commits to. An implementation that could not verify a record without fetching its profile would have made every publisher able to invalidate history.

**A profile may extend the correction classification (section 6.2) for its own fields, but may not reclassify an envelope field.** A publisher knows what a name change means in their domain; nobody knows better than they do. What no publisher may do is decide that changing a record's parents is cosmetic.

**Deprecation is a statement, not a mechanism.** A publisher marks a profile version deprecated in its schema. Records already issued under it remain valid, because a record that stops verifying when a schema changes was never evidence.

---

## 11.7 - Challenge by a third party

A holder may correct their own record and an attester may retract their own attestation. Neither covers the case that matters most in a dispute: someone else says the record is wrong.

Three properties keep this from becoming a way to harass a competitor.

**A challenge never alters the record.** It changes what a verifier is told about it. The record remains exactly as sealed, its commitment unchanged, because a record a stranger can alter is not evidence.

**A challenger shall seal a record of their own claim first**, and name its commitment in the challenge. Filing therefore costs something, is auditable, and puts the challenger's assertion on the same footing as the one they contest. A challenge naming no claim is refused.

**A challenge is signed.** An anonymous challenge is free to make and impossible to answer.

A challenge carries: `challengeId`, `subjectCommitment`, `claimCommitment`, `ground`, a public `statement`, the challenger's identity, `filedAt`, `state`, and a signature. Grounds are `prior-possession`, `descent`, `attestation`, `identity` or `other`. States are `open`, `answered`, `withdrawn` or `resolved`.

**The holder may answer, and is never required to.** Silence is not an admission. Where an answer is given, both statements travel with the record.

**Nothing here is adjudicated.** A verifier is told that a record is contested, on what ground, and whether it was answered. Where a matter has been resolved, the resolution records which outside authority ruled and a reference a verifier can check for themselves. A registry that ruled on a contested claim would be substituting its judgement for a court's, and would stop being usable by either party the first time it did so.

---

## 12 - What is not yet specified

Named so that implementers do not mistake absence for oversight.

**Per-field commitments.** A scheme committing each field as a leaf under a sealed root, so that a holder can prove a shown value is the sealed one, or prove a property of a hidden value, without disclosing the rest. This is what would make the `integrity` grant separable from full disclosure (section 8.1), and what an examiner needs in order to confirm that a test was run and returned a stated result without taking custody of the underlying data.

An independent implementation of this shape exists and has been exercised against records in this format, which is why the entry is worth more than a placeholder. It demonstrates four claim types over a sealed field set: that a shown value is exactly the sealed one; that a sealed number meets a stated threshold without the number appearing anywhere; that two records differ at k or more fields without revealing which or by how much; and that a correction changed no committed field. A claim the sealed data does not support cannot be constructed at all, so nothing is published and nothing is spent.

Specifying it here would have to settle four things that exercising it made plain.

**The committed field set is bounded, and the bound is a cost rather than a limit.** The proving cost is paid over the whole set whether or not every field is used, so a wider set is a slower proof rather than an impossible one. Where a subject carries more fields than one set holds, the fields divide across several records with a parent record naming each by commitment, which is declared descent (section 3.4) rather than a new mechanism. What a split costs is legibility, not soundness: a claim over the whole subject becomes several claims and a sum, and a certificate citing one statement is a different artifact from one citing three.

**The identifier for a committed field set must cover the field paths.** Two sets with the same field names in the same order are otherwise indistinguishable, so a claim about the third field of one part of a subject reads identically to a claim about the third field of another. Where a subject is split, the part must appear in the field path and not only in the document body.

**Proving a shown value is the sealed one establishes authenticity, not confidentiality.** The digest of the shown value is public, because it is the statement being made. A low-entropy value is therefore recoverable from it by anyone willing to guess. That is the correct behaviour for an examiner who has been shown a value and needs to establish afterwards that it was the sealed one, and it must never be described as concealing anything. Threshold and set-membership claims are the ones that hide a value.

**Verification must not require the implementer.** A claim of this kind is recorded in state a verifier can read directly: the claim key is derived from the record, the field, the asserted value and the sequence at which it was recorded, so a verifier who has the record and the contract source can recompute the key and read the result without asking anyone. Any endpoint offered for the same purpose is a convenience. A per-field scheme whose verification depends on the party that issued it would fail the constraint in section 11 that a record survives its registry.

**And the shape does not fit every kind of evidence.** It serves a bounded, curated set of fields whose individual values carry meaning. Where a determination rests instead on statistical distance across hundreds or thousands of values, committing each as a leaf is the wrong instrument at any width, and what would be attested is a laboratory's computation rather than each value it ran over. That is a different trust model and this specification should say which one it is describing.

**Semantic conformance.** The vectors in section 10 establish that two implementations compute identical commitments and fold identical proofs for the same inputs. They do not test whether a field's contents are permissible - the restriction on `payee` in section 3.5 is the first such rule. A conformance profile covering field content is not specified here, and should be defined against a requiring body's audit needs rather than guessed at in advance.

---

## 13 - Comment

This document is published for comment, and specific correction is more useful than general agreement. The classification table in section 6.2 is the part most in need of review by people who adjudicate disputes in a given domain; the authors' assignments there are reasoned but not authoritative.

**Implementations:** TypeScript (reference, published under Apache 2.0 with the conformance vectors), Python, and Rust. All three pass the same vectors.

**Contact:** Hunter Roberts, VeilCore - hunterfrancisroberts@gmail.com

---

*This specification describes a format, not a service. Every property it claims is either demonstrable from the published implementations and vectors, or is stated as a limitation. Where the authors have made a judgement rather than followed a constraint - the field classification in section 6.2 above all - that is marked as such.*
