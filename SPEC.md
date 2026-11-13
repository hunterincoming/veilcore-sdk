# The VeilCore Record Format

**A specification for evidence of prior possession of plant and animal genetic material**

Version 0.1 - August 2026, revised 3 November 2026 (section 3.6.1: a record that names its own key; sections 11.8, 11.9 and 11.11, final: animal, strain and document records; section 11.10, a draft: deal records; section 11.12, a draft: laboratory results version 2; the record format version is unchanged)

---

## Status of this document

This is a draft specification, published for comment. It describes a record format and a verification procedure. It is not a description of a product.

**The format is open.** Anyone may implement it. There is no license fee, no certification requirement, and no dependency on any company for the format to function. Three implementations - in TypeScript, Python and Rust - pass the same 121 conformance vectors, and the five animal-record fingerprints of section 11.8; the TypeScript and Python implementations also check that profile's 25 refusals. All three have the same author, so they show the vectors hold across languages, not that a third party can implement the format from this document alone. An implementation by an unrelated party is the test this document most needs. The vectors cover canonicalisation, commitment computation, inclusion proofs, rejections, attestation payloads, field sets and (since October 2026) the report pairing of section 3.7 and records that name their own key (section 3.6.1); corrections and resolution are implemented in the reference implementation and are not yet part of the vector set.

**Verification is free and requires no account, permanently.** This is a design constraint rather than a pricing decision: a record whose verification can be withheld is not evidence.

---

## 1 - What problem this solves

A person who holds genetic material - a plant variety, a breeding line, a cell culture - may later need to establish three things: that they held it; from a date preceding someone else's acquisition of it; and that material in another party's possession descends from theirs.

These are historical claims, ordinarily supported by the holder's own records - which is the weakest available evidence: records produced by the party relying on them, creatable after the fact.

The obvious remedies fail in specific ways.

**Depositing a physical specimen** fixes the date but requires storage. For asexually reproduced material, long-term storage and recovery are frequently infeasible - the reason USDA's Plant Variety Protection Office exempts such varieties from its deposit requirement.

**Notarising a description** fixes the date but requires disclosing the description to a third party. Where the material is valuable and unprotected, that is the one thing the holder cannot afford. It also does not scale: a breeding programme makes hundreds of selections annually, most never registered, any of which might later need defending.

**Registering with a central authority** requires an authority to exist, to be trusted by every party to a future dispute, and to still exist when the dispute arises. Rights in plant material run twenty-five to thirty years.

**And a mandate does not by itself produce evidence.** Record-keeping rules say that records must exist; they rarely say how anyone later establishes that a record existed when it claims to. The Recommended Uniform State Seed Law, the model law maintained for US states, requires a complete record for each lot - its origin, treatment, germination, purity, kind and variety - and attaches no evidentiary standard to it. The records exist; what they prove depends on who is asked to believe them.

This specification describes a form of record that fixes a date without storage, without disclosure, without a trusted authority, and which produces an answer rather than a document to be interpreted.

---

## 2 - How it works, in five sentences

The holder writes down what they possess, in a defined structure. That description is hashed on the holder's own equipment, together with a random value, producing a **commitment** - a 32-byte number which reveals nothing about the description and which no one can feasibly produce from a different description. Only the commitment is published; the description never leaves the holder's possession. Later, to prove what they held, the holder produces the description and any party can recompute the commitment and compare it to the published one. If the two match, the description is the one that existed when the commitment was published.

---

## 3 - The record

A record has three layers. This separation is what allows the format to be used outside its authors' domain without modification.

**The envelope** is domain-blind. No field in it names a crop, an animal, a plant part, or any subject-specific concept. The test for any proposed envelope field is whether an ornamental propagator, a livestock herd book, and a microbial culture collection would all need it.

**The profile** carries the subject fields. A profile is identified by a versioned string and defined by a JSON schema its publisher maintains. The plant-variety profile is one profile; a body working with fruit varieties or livestock defines its own and reuses everything else. One animal profile is drafted in section 11.8.

**The disclosure vocabulary** names what a holder may grant to a recipient, so that holder, recipient and any adjudicator describe the same disclosure in the same words.

### 3.1 Envelope fields

Required: `formatVersion`, `recordId`, `subjectType`, `profile`, `commitment`, `commitmentAlgorithm`, `anchor`, `sealedAt`, `holder`, `profileData`.

Optional: `subject`, `identification`, `registrations`, `attestations`, `parents`, `terms`, `supersedes`, `jurisdictionBindings`, `extensions`, `ledgerIdentity` (section 3.6), and, for records sealed under `sha256/fields/v1` (section 4.5), `fieldSchema` and `fieldSetRoot`.

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
| `ledger` | The commitment, or a batch root containing it, published in a public chain | No general presumption. Italy's Law 12/2019, Art. 8-ter, gives distributed-ledger timestamps the effect of an ordinary eIDAS electronic timestamp (Art. 41(1): not denied effect, no presumption), subject to technical standards; Chinese courts have accepted blockchain evidence since 2018; US courts authenticate under FRE 901(b)(9) and 902(13)-(14) |
| `rfc3161` | A signed timestamp token from a Time Stamping Authority (RFC 3161). Fields: `token` (the DER TimeStampToken, base64; a verifier also accepts a full TimeStampResp), `tsa`, `qualified`. **What is stamped:** the 32 raw bytes of the record's commitment, or, for an anchor carried on an inclusion proof, of the batch root - never their hex text. The request's messageImprint is the hash of those 32 bytes, as `openssl ts -query -data commitment.bin -sha256` submits it. **An implementation checks:** (1) the imprint's `hashedMessage` equals the hash of the stamped bytes under the imprint's algorithm, which shall be SHA-256, SHA-384 or SHA-512; (2) the `messageDigest` signed attribute equals the hash of the encapsulated TSTInfo, and the content type is id-ct-TSTInfo; (3) the signature over the DER signed attributes, encoded as a SET OF, verifies with the signer certificate's public key, by RSASSA-PKCS1-v1_5 or ECDSA on P-256 or P-384 with SHA-256/384/512, any other algorithm being refused; (4) the signer certificate carries the id-kp-timeStamping extended key usage. The date is the TSTInfo `genTime`. These checks do not establish who the signer is: the certificate chain to a trusted root, qualified status on a trusted list, and revocation are separate checks, and a verifier that has not made them reports them as not checked | Where the TSA is a Qualified Trust Service Provider on an EU trusted list, eIDAS Article 41(2) gives the qualified timestamp a presumption of accuracy (Article 42 sets what makes it qualified), and the burden falls on whoever disputes the date |
| `notarial` | A timestamp applied by a notary or equivalent officer | Follows local rules on notarial acts |
| `opentimestamps` | An OpenTimestamps proof (`.ots`) that the commitment, or a batch root containing it, existed by the time of a Bitcoin block. Fields: `stamps` (what file was stamped: for a batch, the root as 32 raw bytes), `ots` (the file, base64 or a URL), `calendars` | No general presumption. Independent of the issuer and of any other chain; a French court accepted a blockchain timestamp as evidence of authorship in 2025 (Tribunal judiciaire de Marseille, 20 March 2025). A fresh proof is pending until the calendar's Bitcoin transaction confirms |

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

### 3.6 Ledger identity

A ledger contract may keep licenses, lineage and obligations under an identity of its own, separate from the record's content commitment (VeilCore on Midnight does: the identity is a commitment to a secret only the holder knows, and it survives key changes). Fields: `chain`, `identity` (64 lowercase hex characters), and optionally `contractAddress` (64 lowercase hex characters).

**`ledgerIdentity` is committed.** It binds the record's content to that identity: anyone shown the record learns which identity speaks for it, and only the holder of that identity can act for it on the ledger. Without it, the link between a record's content and its ledger identity is the holder's statement, and a holder could point one identity's licenses at a different record.

The identity's own anchor date says nothing about who holds the record now, or about this record's content. A record can change hands through a key rotation or a recovery, which on the ledger looks the same as a holder replacing their own key; and the content is dated only by its own commitment's anchor.

It reveals nothing about the secret behind the identity. It does link the record's content to everything that identity does on the ledger, for anyone shown the record; a holder who wants a record unlinkable leaves it out.

#### 3.6.1 A record that names its own key, without showing it

`ledgerIdentity` puts the identity in the record for anyone shown the record. A registry that stores whole records, and knows which account holds each, could then join an account to everything that identity does on the ledger. And a verifier asked to check a control proof (rule 8 of the VeilCore design note) usually holds only the record's fingerprint, not its content. This section binds the identity to the record for both cases, revealing it to neither.

**Where it applies.** To committed JSON whose fingerprint is anchored on its own: VeilCore's registry anchors the record fields an export carries in its `org.veilcore.registered-fingerprint` extension this way, and `keyBinding` is then one of those fields. It is not an envelope field; the envelope's committed fields (section 4.2) and `formatVersion` are unchanged, and an envelope names its identity with `ledgerIdentity` as above.

`H` is as in section 3.7. All values are 64 lowercase hex characters; anything else shall be refused.

    identity    = H("veilcore:v1:commit",    recordSecret)     on VeilCore's contract, commit()
    keySalt     = H("veilcore:v1:keysalt",   recordSecret)
    keyBinding  = H("veilcore:v1:keybind",   identity, keySalt)
    contentHash = SHA-256 of the canonical serialisation (section 4.4) of the committed fields, keyBinding included
    fingerprint = H("veilcore:v1:keyrecord", keyBinding, contentHash)

**`keyBinding` is a committed field, and the fingerprint is built around it.** The identity can be computed before anything is put on a ledger, so a record is sealed naming it. `keyBinding` reveals nothing about the identity without `keySalt`, which the holder keeps and never places in the record; deriving it from the record secret means the holder's existing backup restores it. Because `keyBinding` is inside the committed fields and also at the top of the fingerprint, as `fieldSetRoot` is in section 4.5, one set of committed fields cannot be paired with two keys, and a verifier can match a key to a fingerprint from hashes alone. The algorithm identifier for such a fingerprint is `sha256/key-bound/v1`; a fingerprint over committed fields with no `keyBinding` is `contentHash` itself, as before.

**What a verifier checks.** Given the fingerprint (from a source it trusts for that record, such as the link the holder sent, matched against the registry's answer), an identity, `keySalt` and `contentHash`: recompute `H("veilcore:v1:keyrecord", H("veilcore:v1:keybind", identity, keySalt), contentHash)`. If it differs from the fingerprint, the identity is not the record's and a verifier shall refuse to treat any proof by it as a proof about the record. If it matches, a control proof by that identity is a proof by the key the record named when it was sealed. `contentHash` reveals nothing about the record's content: the content includes the nonce of section 4.3.

**With a field set.** Committed fields that carry a field set (section 4.5: `fieldSchema` and `fieldSetRoot`, both or neither, each 64 lowercase hex characters) take, in place of the plain SHA-256 above,

    contentHash = H("veilcore:v1:frecord", fieldSetRoot, SHA-256 of the canonical serialisation of the committed fields)

which is the commitment of section 4.5, so a claim proved on a ledger about that commitment is a claim about this record. The fingerprint is built around it exactly as above; with no `keyBinding` the fingerprint is that commitment itself, algorithm `sha256/fields/v1`. A verifier holding a claim's commitment and the record's `keyBinding` recomputes `H("veilcore:v1:keyrecord", keyBinding, commitment)` and compares it with the record's fingerprint; `keyBinding` reveals nothing about the key, so it may be published with the fingerprint. Committed fields carrying only one of `fieldSchema` and `fieldSetRoot`, or either in any other form, shall be refused.

**Records sealed without `keyBinding` remain valid** and their fingerprints are unchanged. For them the link between an identity and the record stays the holder's statement, and a verifier shall say so. A verifier told by a registry that a record carries a `keyBinding` shall not fall back to that weaker reading when a holder's link leaves `keySalt` and `contentHash` out.

**What it does not establish.** That whoever controls the key now is the person who sealed the record (section 3.6: rotations, recoveries and sales look alike), who that person is, or who bred the subject. And the identity's own anchor dates the key, not the record: a key anchored early can be named by a record sealed later. The record and its key are dated together by the record's fingerprint's own anchor (section 5).

### 3.7 A report paired on a ledger

A holder may pair a report - a laboratory's DNA report, say - with a ledger identity, so the ledger shows that whoever controlled that identity at a date had the report, or its SHA-256, by then. The value put on the ledger is

`binding = H("veilcore:v1:dnapair", reportHash, identity, salt)`

where `H` is as in section 4.5 (SHA-256 over 32-byte elements, the first the tag in UTF-8 right-padded with zero bytes to 32), `reportHash` is the SHA-256 of the report file, `identity` is the ledger identity (section 3.6) of the record pairing it, and `salt` is 32 bytes from a cryptographically secure generator, kept by the holder with the report. Each input is 64 lowercase hex characters; anything else shall be refused.

**Why not the report's hash itself.** A value on a public ledger can be copied, even from a transaction still waiting to be included, and paired under another identity first. Which of two pairings of a raw hash came first then shows nothing about who had the report first. The binding reveals nothing about the report (without the salt nobody can test a guess), holds only for the identity inside it, and cannot be made for another identity without the report's hash. That hash stays with the holder until they show it only if it was never published: once a ledger carries the raw hash (a pairing of the hash itself, by anyone), anyone can make a binding of it for their own identity without ever seeing the report.

**What a verifier checks.** Given the report, the salt, the identity and the ledger transaction: hash the report themselves, recompute the binding, and confirm the transaction paired that value under that identity (on VeilCore's contract: verifier rule 9 of its design note, `docs/design.md` in the veilcore repository (github.com/hunterincoming/veilcore)). A verifier given only the report's hash, not the report, shall not accept: the hash is all anyone needs to make a binding. What an acceptance establishes is this and no more: whoever controlled that identity at the transaction's time had the report, or its SHA-256, by then. A verifier shall also look for a pairing of the raw hash on the same ledger before the binding's transaction; if there is one, the hash was public from then on, and the verdict shall say so. And where the identity has changed keys since (section 3.6: a sale, a new key and a recovery from a theft look the same), an earlier key holder made the pairing, and the verdict shall say so. It does not show who holds the identity now, or that nobody else had the report earlier: the laboratory that wrote it did. Nothing in the binding says what the report says.

**The holder shall keep the salt with the report**, and back it up: without it the pairing can never be shown, and nothing else (a record secret, say) brings it back. A salt shall not be all one byte value. Once disclosed, it lets anyone holding the report recognise the pairing.

---

## 4 - The commitment

### 4.1 Algorithm

The commitment is SHA-256 over the canonical serialisation of the committed fields, expressed as lowercase hexadecimal. The algorithm identifier is `sha256/canonical-json/v1`.

**This deliberately requires no distributed ledger, no specialised runtime, and no dependency on any particular software.** Any implementation, in any language, with a SHA-256 function, can compute and verify a commitment. This is the property that permits a registry the authors do not operate to issue records in this format.

Binding a commitment to a ledger is a separate operation described by the anchor's own algorithm identifier, and only that operation is chain-specific.

### 4.2 Committed fields

The commitment covers, exactly and exhaustively:

`attestations`, `commitmentAlgorithm`, `extensions`, `fieldSchema`, `fieldSetRoot`, `formatVersion`, `holder`, `identification`, `jurisdictionBindings`, `ledgerIdentity`, `parents`, `profile`, `profileData`, `recordId`, `registrations`, `sealedAt`, `subject`, `subjectType`, `supersedes`.

**`attestations` and `parents` are always committed**, as an empty array when absent. Every other optional field is committed only when present, and is omitted rather than serialised as null.

The list is exhaustive because a verifier that includes a different set computes a different commitment and reports a genuine record as altered. A field added to this specification without being added to this list is a field two conformant implementations will disagree about.

It does **not** cover `anchor` (a statement about the commitment) or `terms` (issued and revoked after sealing).

**A record missing a required field (section 3.1), or carrying any committed field as `null`, shall be refused.** Absent `attestations` and `parents` are committed as empty arrays; `null` is not absent.

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

1. **UTF-8**, normalised to **Unicode NFC** — **both keys and string values**. Normalise before sorting. If two keys in the same object are equal after normalisation, **the record is invalid**; an implementation shall reject it rather than pick one, because picking one means two implementations pick differently. **A string containing an unpaired surrogate is invalid** (keys included): it has no UTF-8 form, an encoder that substitutes U+FFFD makes different strings commit alike, and some languages cannot represent it at all.

2. **Object keys sorted by Unicode code point.** **This is not JavaScript's default sort**, which compares UTF-16 code units and orders characters above U+FFFF incorrectly relative to characters in the range U+E000–U+FFFF. An implementation in JavaScript shall sort by code point explicitly. This is a real divergence, not a theoretical one: `{"｡":1,"😀":2}` orders differently under the two rules.

3. **No insignificant whitespace.**

4. **A null is invalid anywhere in a committed field**, at any nesting depth. Absent optional fields are omitted; a field whose value is null makes the record invalid and an implementation shall reject it. Earlier drafts said an omitted field and a null field must not differ, which is unimplementable without also saying whether a nested null is dropped or serialised — implementations diverged on exactly that. Rejection is the only rule with one reading.

5. **Array order is preserved and never sorted.** Parent order is meaningful in some domains.

6. **Timestamps** in RFC 3339, UTC, `Z` suffix, second precision.

7. **Strings** escaped per RFC 8785 section 3.2.2.2 — the shortest escaping, using the two-character forms where they exist and lowercase `\uXXXX` otherwise.

8. **Numbers** are serialised per RFC 8785 section 3.2.2.3, which is ECMAScript's shortest round-trip representation. `1e-7` serialises as `1e-7`, never `1e-07`; `95.0` serialises as `95`, since JSON cannot distinguish them and JavaScript does not. Non-finite values are invalid. **A number whose magnitude exceeds 2^53 − 1 (9007199254740991) is invalid**, integer or not: beyond it a double no longer holds every integer, and an implementation that reads big integers exactly disagrees with one that rounds them. Such a value belongs in a string. This is stricter than RFC 8785.

   **A profile may require integers.** Where a value carries a laboratory measurement, a profile publisher should consider requiring it as a string rather than a float: implementations agree on integers within ±2^53 and on strings, and every remaining disagreement about numbers lives in the space between.

> **Note (not normative).** This revision sets no maximum nesting depth and does not say what to do with a JSON text that repeats a key in one object. The implementations differ: the TypeScript one's depth limit depends on the stack it runs on, and the Rust one refuses input nested deeper than about 125 levels; a JSON parser commonly keeps one of two duplicate keys without saying so. A future revision will set a maximum depth (proposed: 64) and require rejecting duplicate keys. Until then, do not rely on a record nested deeper than 64 levels or one whose JSON text repeats a key.

Rule 1 is easy to overlook and produces a failure invisible to a human reader: an accented character composed as a single code point and the same character composed as a base letter plus a combining accent are visually identical and hash differently.

### 4.5 Field sets: `sha256/fields/v1`

A record may additionally commit up to sixteen values as separate leaves, so that a holder can later prove one fact about one value - that it is a stated value, that a number meets a bound, that two records differ in enough values, that a correction left some values unchanged - without disclosing the rest. The proofs are made on a ledger (the reference is the VeilCore claims contract); everything in this section is plain SHA-256.

**Hashes.** `H(tag, a, b, ...)` is SHA-256 over the concatenation of 32-byte elements, the first being the tag in UTF-8 right-padded with zero bytes to 32. A **count** is an unsigned integer below 2^64 written little-endian into 32 bytes. Two hashes below are not of this form (the leaf and the set root). Each hashes a fixed layout (55 and 560 bytes) and sits at a fixed position, the leaves inside the set root and the set root inside the commitment, so neither can stand in for another hash in this section. (A text value is SHA-256 of arbitrary text and so could, in principle, equal a leaf; it never occupies a leaf's position.)

**Why the layout is what it is.** Every claim recomputes these hashes inside a zero-knowledge proof, where one SHA-256 block costs about two thousand circuit rows, and the memory a proof needs doubles with each doubling of rows. A leaf is one block and the root is one hash, so a claim over two whole records needs 56 blocks rather than 135, and each claim can be proved on an ordinary computer by the holder, who then never hands the values to anyone else to prove for them.

**Schema.** A field schema is a published JSON document with an `id` (a non-empty string naming its publisher and version), a `title`, a `slots` list and an integer `k`. Each slot entry is an object with `slot` (0 to 15, each at most once), `type` (`uint` or `text`), `path` (a non-empty string saying what the slot holds), and optionally `unit` (a string), `scale` (a positive integer: the stored number is the measured value times `scale`), `comparable` (true or false) and `format`. A `comparable` text slot shall declare a `format`, and `format` is allowed only on text slots:

| `format` | Canonical form | Example |
|---|---|---|
| `allele-pair` | two allele sizes, decimal, no leading zeros, at most nine digits each, smaller first, joined by `/` | `180/184` |
| `allele` | one allele size, decimal, no leading zeros, at most nine digits | `233` |
| `code` | an upper-case letter or digit, then up to 63 upper-case letters, digits, `.`, `_` or `-` | `HM-3` |

A value in a slot with a `format` shall be in that form; anything else shall be refused rather than normalised. Distinctness compares values byte for byte, so one genotype written two ways would otherwise count as a difference.

`k` is the distinctness threshold: at least 1, at most the number of comparable slots. The schema id is

`schemaId = H("veilcore:v1:fschema", SHA-256(canonical JSON of the schema), terms)`

where `terms` is 32 bytes: the comparable mask in bytes 0-1 and the numeric mask in bytes 2-3 (bit *i* set for slot *i*, little-endian; the numeric mask names every `uint` slot), `k` in byte 4, and zero in bytes 5-31. Because the masks and `k` are inside the id, a claim cannot choose its comparable slots or threshold, and a range claim can be refused on a slot the schema does not call a number. **A verifier shall obtain the schema document from its publisher and recompute the id**; a claim names an id, and an id is only as meaningful as the document behind it.

**Slot values.** Each of the sixteen slots holds 32 bytes:

- a `uint` value: the number in bytes 0-7, little-endian, **byte 8 set to 1**, the rest zero;
- a `text` value: SHA-256 of its UTF-8 after NFC normalisation (text containing an unpaired surrogate shall be refused);
- an absent value: 32 zero bytes.

**The present-marker in byte 8 is required.** Without it the number 0 and an absent value would be identical, and a record with no germination test could prove "at most 0.5% other-crop seed".

A value shall match its slot's declared type, and a slot the schema does not describe shall be absent. In the vectors a value is written `{"uint": "<decimal, no leading zeros>"}`, `{"text": "..."}` or `null`.

**A value in a field set shall not also appear in the record's committed JSON.** The schema's paths name the holder's private copy, not committed fields; a value in both places would be disclosed with the JSON and could contradict itself.

**Salts.** `salt_i` is the first 23 bytes of `H("veilcore:v1:fsalt", fieldSecret, count(i))` (184 bits), where `fieldSecret` is 32 bytes from a cryptographically secure generator, kept with the holder's private copy of the record. **The field secret shall never be inside the committed JSON or any disclosure of it, shall not be derived from the nonce, and shall not be reused across records**: anyone who could derive the salts could guess low-entropy values back from their leaves.

**Leaves and root.** `leaf_i = SHA-256(value_i || salt_i)` (55 bytes, one SHA-256 block), and

`fieldSetRoot = SHA-256("veilcore:v1:fset" || schemaId || leaf_0 || ... || leaf_15)`

where the tag is exactly those 16 ASCII bytes, unpadded, so the input is 560 bytes.

**Commitment.** The envelope carries `fieldSchema` (the schema id) and `fieldSetRoot`, both as 64 lowercase hex characters and both committed in the JSON, and

`commitment = hex(H("veilcore:v1:frecord", fieldSetRoot, jsonDigest))`

where `jsonDigest` is the SHA-256 of the canonical serialisation of the committed fields exactly as in sections 4.1-4.4. A field-set record missing either field, or carrying either in any other form, shall be refused; so shall a `sha256/canonical-json/v1` record carrying either, and any record whose `commitmentAlgorithm` is not exactly one of the two identifiers in this specification. The nonce of section 4.3 is still required.

Because `fieldSetRoot` is in the JSON, anyone shown the JSON sees which field set it belongs to, and one JSON cannot be paired with two field sets. `fieldSetRoot` reveals nothing about the values. Disclosing the committed JSON (for `integrity`, section 8.1) does not disclose the values in the field set.

**An opening** of slot *i* is its value, its salt, and the sixteen leaves. A verifier recomputes `leaf_i` from the value and salt, checks it is the *i*-th of the sixteen, and recomputes the root. The other fifteen leaves are salted hashes and disclose nothing about their values.

**Claims** (reference: the VeilCore claims contract, `contract/src/veilcore-claims.compact`, and its design note, `docs/claims-design.md`, in the veilcore repository (github.com/hunterincoming/veilcore); run end to end on Midnight preprod on 4 October 2026; not on mainnet as of that date) are proved against the record commitment and published on the ledger:

- **value**: slot *i* holds a stated value. The value is published: this establishes authenticity, never confidentiality.
- **range**: a `uint` slot is at least, or at most, a bound. The number is not published.
- **distinct**: two records under the same schema differ in at least `k` comparable slots, counting only slots present in both. Which slots differ, and how many, are not published. It shall be reported as "differs in at least k comparable values", never as a determination of distinctness, which is the examining body's.
- **unchanged**: two records under the same schema have equal values outside a published mask. It establishes nothing else: not which record is the correction, nor that either names the other in `supersedes`.
- **attested**: a laboratory signed a record. The key is published. Read together with any claim above on the same record, it makes that claim about values the laboratory sealed; a distinct or unchanged claim needs one for each record it names.

**The laboratory's signature shall be over the record commitment**, not the field-set root, so it cannot be moved to another record built around the same values; it states that the laboratory sealed that record. Which keys are laboratories is the verifier's decision (section 7).

**What a verifier of a claim shall check:**

1. The claim is on the published claims contract, whose verifier keys match the published fingerprints, and was read per call, not per transaction or block.
2. Every record named is anchored; for **distinct**, the reference's anchor predates the claim's purpose (an application, a dispute).
3. The schema document, obtained from its publisher, recomputes to the claim's schema id; the slot has the type the claim needs; `scale` and `unit` are applied as stated.
4. Where the committed JSON is held: `commitmentAlgorithm` is exactly `sha256/fields/v1`, and `fieldSchema` and `fieldSetRoot` match.
5. Whether the record is current. A claim states a fact about a record as sealed; where currency cannot be established, the claim shall be reported as about the record as sealed.
6. For a laboratory-signed claim: the key belongs to a laboratory the verifier trusts and was valid at the time of the claim transaction (the signature can be made later than the record's anchor).
7. For **distinct**: the reference record is identified by someone other than the prover.
8. For **unchanged**: the mask leaves at least one slot the schema describes unable to change. Slots the schema does not describe are empty in every record, so a mask over every described slot says nothing and the claim shall be refused, as one over all sixteen is. And the newer record names the older in `supersedes`. A `recordId` is scoped to its issuer, so a match on `recordId` counts only when both records have the same holder. Where the supersedes block also states the older record's `commitment` (optional; section 6 does not yet list it), match by that instead.
9. What earlier claims on the same slot have already published (below).

**Disclosure accounting.** Every published value or bound tells the world something, and a series of range claims narrows a hidden number: a refusal to prove leaks as much as a proof. An implementation that offers claims shall show the holder what claims already published on a slot reveal before proving another, and shall not prove a claim at a third party's request without the holder's confirmation.

**Limits that shall be stated wherever claims are offered.** A distinctness claim needs one party who holds both value sets (a breeder comparing its own varieties, or a laboratory that tested both); it does not let two parties compare values neither will show the other. Anyone the holder gives an opening to can publish a value or range claim about that slot. Sixteen slots is the bound per record; a subject with more divides across records joined by declared descent (section 3.4). Statistical distance over thousands of values is the wrong shape for per-slot claims.

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

**The signed material is, exhaustively:** `attestationId`, `type`, `subjectCommitment`, `documentHash`, `hashAlgorithm`, `issuedAt`, and the attester's `publicKey`, `displayName`, `role` and `accreditation`. Absent optional fields are omitted rather than serialised as null, per section 4.4.

The attester's identity is inside the signature in full, not by its key alone. An implementation that signs the key and leaves `displayName`, `role` or `accreditation` outside it produces attestations anyone holding one can rewrite: a small laboratory's genuine report becomes an accredited one, the signature byte-identical and still verifying, and section 7.2 reports the forged tier because those are the fields it reads. This is stated exhaustively because it was implemented narrowly here first, and the narrow reading was a faithful one of an earlier wording.

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

**Specified here, not yet implemented.** The reference implementation verifies an attestation against the key carried inside it and reports a boolean. It performs no registry lookup, does not compare `issuedAt` against a validity interval, and has no `suspect` state. Everything in this section describes what a conforming verifier shall do once a registry exists to be consulted; no registry does. Stated plainly because a reader planning around rotation would otherwise assume it is handled, and because section 7.1's remedy for a lost key points at a mechanism nothing implements.

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

**A per-field commitment scheme is what makes it separable**, by committing each field as a leaf and sealing a root, so that a holder can demonstrate that a shown value is the sealed one without showing the rest. Section 4.5 specifies one for up to sixteen values per record.

For a record sealed under `sha256/canonical-json/v1`, and for every value in the committed JSON of any record, an implementation shall not present `integrity` to a holder as a disclosure narrower than full disclosure of the committed fields. Only values in a field set can be proved one at a time. A grant that a holder believes is narrow, and is not, is worse than no grant.

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

**It establishes prior possession of the record, not of material.** What is shown is that a party held this description, with its nonce, by the date of the anchor. It does not show that the party presenting it now is that party: a ledger identity's anchor date says nothing about who holds the record today (section 3.6). A record that names its own key (section 3.6.1) lets a control proof be tied to the record, which shows that whoever answered controls the key the record named, not that they sealed it. Nor does the earlier of two records or ledger pairings carrying the same raw report hash show who had the report first; a hash, once seen, can be copied. A pairing bound to an identity (section 3.7) shows that whoever controlled that identity at its date had the report, or its SHA-256, by then - unless the raw hash was on the ledger earlier. It does not show that any material is the subject described, or that material was ever in their hands.

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

Vectors cover canonicalisation - key ordering, omitted versus null, array order preservation, NFC normalisation, nested sorting, numeric and boolean forms - commitment computation across a range of record shapes, including the requirement that changing the anchor does not change the commitment, and inclusion proofs across batch sizes chosen so that an implementation which duplicates an odd node rather than promoting it will disagree. Field-set vectors (section 4.5) cover schema ids, slot values including the number 0 against an absent value, NFC text, salts, set roots and openings, with refusals for every validation rule and for field-set records missing their bindings. Together these are the 100 record-format vectors. One further vector (`pairings`) gives the binding of section 3.7 for fixed inputs; it is not part of the record format, and an implementation that does not offer ledger pairings may leave it out and say so. Twenty further vectors (`keyBoundKeys`, `keyBoundRecords`, `keyBoundChecks`, `keyBoundRefusals`) cover section 3.6.1: a key, its salt and its binding from a record secret, record fingerprints old and new, whether a key matches a record, and refusals of a malformed `keyBinding`. They are copied unchanged from `key-bound-v1.json`, published with the VeilCore web application and checked there and by the VeilCore registry, so the implementations are tested against values none of them computed. They are not part of the envelope format either; an implementation that does not read key-bound fingerprints may leave them out and say so. Thirty more (`animalRecords`, `animalRefusals`) cover the animal profile of section 11.8: five records whose fingerprints are computed exactly as any record's, and twenty-five sets of fields the profile refuses. They are copied unchanged from `animal-individual-v1.json`, published with the VeilCore web application. They test a profile, not the record format; an implementation that does not check the animal profile runs the records and leaves the refusals out (`--without-animal-profile`), and says so. Thirty more (`strainRecords`, `strainRefusals`) do the same for the strain profile of section 11.9, copied unchanged from `strain-v1.json` (`--without-strain-profile`). Eighty-eight more (`labStatements`, `labStatementRefusals`, `labBindings`, `markSeals`, `markRefusals`, `labNameBindings`, `labNameBindingRefusals`) cover laboratory results version 2 (section 11.12), copied from `lab-result-v2.json`; an implementation that does not offer them leaves them out (`--without-lab-results`) and says so.

**Conformance is demonstrated, not asserted.** The vector set and a runner are published with the reference implementation. The runner communicates with an implementation over standard input and output, so implementations in any language can be tested.

A deliberately non-conformant implementation is published alongside them, so that the suite can be shown to detect failure rather than merely to pass.

**The runner distinguishes a refusal from a failure to run.** An implementation that produces no output fails the rejection vectors rather than passing them. Before August 2026 it did not, and a command that did nothing at all scored full marks on that section - a suite that scores silence as a refusal cannot tell a correct implementation from a missing one.

**What conformance does not cover.** These vectors establish that two implementations compute identical commitments and fold identical proofs for the same inputs. They do not establish that a field's contents are permissible - see section 12.

---

## 11 - Design constraints

Recorded because they explain choices that would otherwise look arbitrary, and because an implementer should know which properties may not be traded away.

**Verification is free and requires no account, permanently.** A record whose verification can be withheld is not evidence. Fees may attach to creating a record; never to checking one.

**The format itself is free to implement, permanently.** There is no license fee for using this specification and no permission required. Certification that an implementation is conformant would be a separate service that anyone could offer; none is offered today. The conformance vectors are published, so any party can test any implementation without asking. A format that charges for its own use does not become infrastructure.

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

A profile defines the subject fields for a domain. The plant-variety profile is one; a body working with fruit varieties, ornamentals or livestock defines its own.

**Nobody grants permission to define a profile.** A profile is identified by an authority and a name, resolved the same way a record is:

    veilcore/profile/plant-variety/v1     published by the authors of this specification
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

## 11.8 - Animal records: the animal-individual profile

**Version 1 is final (16 October 2026).** Any change to its committed fields is a new profile, `veilcore/profile/animal-individual/v2`, and records under v1 keep checking exactly as they do. This section defines one profile, `veilcore/profile/animal-individual/v1`, published by the authors of this specification. A record under it describes one animal, logged by its breeder, its holder or a registry. The record format version is unchanged.

**The fingerprint rules do not change.** A record's fingerprint is computed exactly as for any record: SHA-256 of the canonical serialisation (section 4.4) of its committed fields, and, when those fields carry a `keyBinding`, `H("veilcore:v1:keyrecord", keyBinding, contentHash)` (section 3.6.1). The profile says only which fields are committed and in what form. A record sealed under any other profile, or under none, is computed and checked exactly as before.

**Committed fields.** Exactly these, every one present, none other:

| Field | What it holds |
|---|---|
| `profile` | `veilcore/profile/animal-individual/v1` |
| `species` | The species, as the holder writes it. Not empty |
| `breed` | The breed, or empty |
| `name` | The animal's name, or empty |
| `individualId` | Its individual ID exactly as written (an ear tag, a national ID), or empty |
| `idScheme` | The ID scheme the individual ID belongs to, free text ("Japan cattle ID (10 digits)", "ear tag"). Empty exactly when `individualId` is |
| `sex` | `female`, `male` or `unknown` |
| `dateOfBirth` | `YYYY-MM-DD`, a real date, or empty. The holder's statement, like `claimedCreationDate` |
| `parents` | The sire and the dam, as below |
| `breeder` | The breeder or holder. Not empty |
| `herd` | Herd or farm, or empty |
| `notes` | Free text, or empty |
| `photoFingerprints` | SHA-256 of each photo, 64 lowercase hex characters each |
| `loggedAt` | When it was sealed, milliseconds since 1970 by the sealing device's clock, a whole number |
| `nonce` | 32 to 64 random bytes, lowercase hex (section 4.3) |
| `keyBinding` | Optional, as in section 3.6.1 |

`name` and `individualId` shall not both be empty.

**Canonical form.** A value in any other form shall be refused, never tidied: one animal written two ways would seal as two different records. The one-line fields (`species`, `breed`, `name`, `individualId`, `idScheme`, `breeder`, `herd`, and a parent's `name` and `individualId`) are text of at most 200 characters, with no control character (line breaks and tabs included) and no white space at either end. `notes` is text of at most 20,000 characters. Text is NFC-normalised by the serialisation (section 4.4, rule 1). The individual ID is compared as written; this profile does not normalise any national scheme's numbers.

**Parents.** `parents` lists at most a sire and a dam, the sire first, using the roles `sire` and `dam` (section 3.4). Each entry is `{ role, name, individualId }` and, when the parent is a record the holder logged, `recordId`, naming it. `name` and `individualId` may be empty; an entry with neither and no `recordId` shall be refused. A parent is the holder's declaration (`declaredBy: holder` in an envelope), not a parentage test.

**In an envelope.** `subjectType` is `animal-genetic-material`; `subject.name` is the name, `subject.originator` the breeder, `subject.taxon` the species and `subject.claimedCreationDate` the date of birth. The parents carry their role. `profileData` carries `breed`, `sex`, `individualId`, `idScheme`, `herd`, the parents' individual IDs and `notes`, with the nonce.

**What an animal record is offered.** Everything that does not depend on the subject being a plant: the dated record and the key it names (section 3.6.1); a DNA report saved to the record, paired on a ledger (section 3.7) and dated by a record of its own; the sire and dam, linked to their own records where the holder logged them; a laboratory's signed receipt for a sample and its signed report (sections 3.3 and 7); selective disclosure, where the sire and dam are shown under `parent-names` and the individual ID and its scheme under a grant of their own; corrections (section 6).

**What it is not offered, and why.** The claims of section 4.5 are not offered for animal records. This profile defines no field set, and the claim that motivates them, **distinct** ("these two records differ in at least k comparable values"), answers a question about varieties against a threshold an examining body sets. The questions asked of an animal's DNA are identity (is this sample from the animal in the record?) and parentage (are the stated sire and dam compatible with it?). Cattle tests for both commonly use standard STR (microsatellite) panels, and increasingly SNP panels. Either way the answer is a match or an exclusion that a laboratory works out across two or three profiles, not a count of differing slots, so it is attested by the laboratory's signed report rather than proved one value at a time.

**Agreements (from 29 October 2026).** Agreements, royalties and terms (section 3.5) are offered for animal records, with terms of their own: the rights are breeding with the licensee's own animals; breeding and collecting semen or embryos for their own use; or breeding, collecting and selling semen, embryos or breeding stock; and a royalty is charged per dose, per offspring born or per unit sold. The terms carry `subject: "animal"`, so both parties' tools word them the same way. An offspring royalty rides on animals later logged with the record as sire or dam, both holders confirming (section 3.5).

**Vectors.** `animal-individual-v1.json` gives records under this profile (their fields, canonical bytes, content hash and fingerprint, with and without a key) and fields that shall be refused. It is published with the VeilCore web application and checked there, by the VeilCore registry, and by the TypeScript and Python implementations; the Rust implementation checks the fingerprints. Like the profiles themselves, it is outside the 100 record-format vectors of section 10.

**What it does not establish.** Everything in section 9.3 holds. In particular a record establishes that a description of an animal existed by a date, not that a given animal, carcass or cut is that animal, and not who holds the animal now. An individual ID in the record is the holder's statement; that the ID belongs to the animal is for the scheme that issued it to say.

## 11.9 - Strain and line records: the strain profile

**Version 1 is final (3 November 2026; published as a draft on 22 October).** This section defines one profile, `veilcore/profile/strain/v1`, published by the authors of this specification, for one microbial strain, cell line or insect line. Any change to its committed fields is a new profile, `veilcore/profile/strain/v2`, and records under v1 keep checking exactly as they do. The record format version is unchanged.

**Why one profile for all of these.** A culture collection, a cell bank and an insect-rearing facility record the same shape: what it is (a kind and a species), what it is called (a name and the holder's own designation), where copies are deposited (culture collection or patent deposit numbers), how it was made, which generation or passage, and which strain or strains it came from. A standard that needed a new profile for every organism would not be adopted by any of them.

**The fingerprint rules do not change**, exactly as in section 11.8: SHA-256 of the canonical serialisation of the committed fields, folded with a `keyBinding` when one is present (section 3.6.1).

**Committed fields.** Exactly these, every one present, none other:

| Field               | What it holds                                                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `profile`           | `veilcore/profile/strain/v1`                                                                                                   |
| `group`             | One of `bacterium`, `archaeon`, `yeast`, `filamentous-fungus`, `microalga`, `protist`, `virus`, `cell-line`, `insect`, `other` |
| `species`           | The species, as the holder writes it. Not empty                                                                                |
| `name`              | The strain's name, or empty                                                                                                    |
| `designation`       | The holder's own designation for it, or empty                                                                                  |
| `deposits`          | At most 8 deposit numbers, each as the depositary writes it ("NBRC 10217"), none empty, none repeated. May be empty            |
| `method`            | How it was made, free text ("wild isolate", "neutron beam irradiation"), or empty                                              |
| `generation`        | Generation or passage, free text ("M2", "P5"), or empty                                                                        |
| `madeOn`            | `YYYY-MM-DD`, a real date, or empty. The holder's statement, like `claimedCreationDate`                                        |
| `parents`           | At most two parent strains, as below                                                                                           |
| `maker`             | Who made or isolated it. Not empty                                                                                             |
| `notes`             | Free text, or empty                                                                                                            |
| `photoFingerprints` | SHA-256 of each photo, 64 lowercase hex characters each                                                                        |
| `loggedAt`          | When it was sealed, milliseconds since 1970 by the sealing device's clock, a whole number                                      |
| `nonce`             | 32 to 64 random bytes, lowercase hex (section 4.3)                                                                             |
| `keyBinding`        | Optional, as in section 3.6.1                                                                                                  |

`name` and `designation` shall not both be empty.

**Canonical form.** As in section 11.8: a value in any other form shall be refused, never tidied. The one-line fields (`species`, `name`, `designation`, `method`, `generation`, `maker`, each deposit, and a parent's `name` and `deposit`) are text of at most 200 characters, with no control character and no white space at either end. `notes` is at most 20,000 characters. A deposit number is compared as written; this profile does not normalise any collection's numbering.

**Parents.** `parents` lists at most two parent strains: one for a mutant, an isolate's subculture or an edited line; two for a cross, a mating or a fusion. Each entry is `{ name, deposit }` and, when the parent is a record the holder logged, `recordId`, naming it. An entry with no name, no deposit and no `recordId` shall be refused. A parent is the holder's declaration, not a test.

**In an envelope.** `subjectType` is `other` (section 3.1's list has no microbial or cell subject), and the profile says what it is. `subject.name` is the name, `subject.originator` the maker, `subject.taxon` the species and `subject.claimedCreationDate` the date made or isolated. `profileData` carries `group`, `designation`, `deposits`, `method`, `generation`, the parents' deposit numbers and `notes`, with the nonce.

**What a strain record is offered.** Everything that does not depend on the subject being a plant: the dated record and its key; a DNA report (for a strain, typically a genome sequence or a typing result) saved to the record and dated by a record of its own; parent strains, linked where the holder logged them; a laboratory's signed receipt and report; selective disclosure, where the parent strains are shown with their deposit numbers under `parent-names`; corrections (section 6).

**What it is not offered.** The claims of section 4.5, for the reason given in section 11.8.

**Agreements (from 29 October 2026).** A license for a strain turns on use, subculture and derived strains, not on propagation from a variety, so it has terms of its own: use only; use and subculture for the licensee's own production; or use, subculture and making derived strains; with a royalty per production batch or per unit sold, and an optional royalty on derived strains declared from the record. The terms carry `subject: "strain"`.

**What it does not establish.** Everything in section 9.3 holds. A strain record establishes that a description of a strain existed by a date. It is not a deposit: it does not replace a deposit with a recognised depositary, which is what patent procedure in most jurisdictions relies on for a microorganism, and a deposit number in the record is the holder's statement until the depositary confirms it. It does not establish that a culture is viable, pure, or the strain described.

**Vectors.** `strain-v1.json` gives records under this profile and fields that shall be refused. It is checked by the VeilCore web application, the VeilCore registry, and the TypeScript and Python implementations here; the Rust implementation computes the fingerprints and leaves the profile's refusals out (`--without-strain-profile`). Like the other profiles' vectors, it is outside the 100 record-format vectors of section 10.


## 11.10 - Deal records (draft)

A deal record is the signed messages of one license deal, as either side keeps them. It lets a third party (a buyer, a court, a lender) read a royalty history that the payer signed, rather than one the payee typed.

**Shape.** A JSON object: `v` is `veilcore/deal-record/v1`; `keys.issuer` and `keys.licensee` are the deal's two Ed25519 public keys, 32 bytes as lowercase hex; `license` names the license commitment and the issuing record; `messages` is a list of `{ message, signature }`, and may carry other fields a reader ignores, except `seq`: the registry's sequence number for that message, a positive integer, which the sender does not choose. Each `message` has `type`, `from` (`issuer` or `licensee`) and `at` (milliseconds since 1970, signed), plus the fields of its type.

**Signatures.** A message's `signature` is 64 bytes, lowercase hex: Ed25519 (RFC 8032) by the key of the side named in `from`, over the UTF-8 bytes of `veilcore/deal-message/v1` followed by a newline (0x0A), followed by the canonical form of the message (section 4.1). A verifier shall refuse a small-order or non-canonically encoded public key (section 7).

**Who sends what.** A message counts only when its signature verifies and it comes from the side that may send its type: the issuer sends `terms`, `payout`, `reply`, `received`, `credential`, `handon` (naming a new holder's license commitment) and `handon-off` (calling that off); the licensee sends `agree`, `plant-record`, `statement`, `paid` and `handon-ask`. A message of a type a reader doesn't know is reported as unread, not as a failure, once its signature verifies. A `reply`, `paid` or `received` names its statement by the statement's own signature (`statementSig`), and counts only if that statement is in the record and counts. **Order.** A reader orders the messages by `seq` when every counted message carries a distinct one; otherwise by `at`, and says so, because `at` is each sender's own clock and either side can set it to anything. **One statement once.** Two `statement` messages are the same statement when they say exactly the same thing: their canonical forms (section 4.1) are equal once `from`, `at` and `statementId` are removed. Every other field counts, including one a reader does not know: two statements that differ in it are two. The period is one of the fields, so the same statement is always for the same period; one message saved twice is the same case. A reader counts the first in the order above and reads the others as that one: a `reply`, `paid` or `received` naming any of their signatures counts for the first, under the rules that follow, so a resend signed again never doubles what is owed. A licensee who means a second statement for a period with the same figures says so in a field, for example a `note`. `test/fixtures/deal-record-copies.json` is the cross-check: two copies and a reply to the second, and a third statement that differs only in one more field. The first `reply` for a statement stands; a `paid` counts only for a statement whose first reply is `accepted`; a `received` only for a statement with a counted `paid`; later ones are noted and ignored. Amounts are decimal strings and compare as numbers ("10" equals "10.00").

**Settled.** What a statement leaves to pay is `amountOwed` less the `taxWithheld` the statement itself declares, if any. A statement is settled when the licensee signed `paid` for at least that amount, in the statement's currency, and the issuer signed `received` for the same amount in the same currency. A `paid` for less, or in another currency, is a short payment: the rest stays owed, and the statement is not settled even if the short amount is confirmed. Only settled amounts are totalled as paid.

**What it does not establish.** That the two keys belong to two different people: anyone can make both and sign a whole deal with themselves. A reader relying on the history should confirm with the licensee that the licensee key is theirs. It does not establish that money moved, except as both sides' signed statements; a payment made on a public chain can also be checked there.

**Reference.** `checkDealRecord` and `veilcore deal <file>` in this package. `test/fixtures/deal-record-app.json` was made by the VeilCore web application's own code and is the cross-check for other implementations.

---

## 11.11 - Document records: the document profile

**Version 1 is final (31 October 2026; published as a draft on 29 October).** This section defines one profile, `veilcore/profile/document/v1`, published by the authors of this specification, for one document: a permit, a certificate of analysis, a laboratory report, a contract, a protocol, a transport document, an invoice. Any change to its committed fields is a new profile, `veilcore/profile/document/v2`, and records under v1 keep checking exactly as they do. The record format version is unchanged.

**What it is for.** Genetics work runs on paperwork, and disputes start there: which certificate was sent, which version of a protocol was in force, which transport document went with which shipment. A document record dates the exact bytes of a file without the file ever being in the record or leaving the holder's device: the record holds each file's SHA-256, name and size. This is the shape of document timestamping (OpenTimestamps and similar); a record adds what any record here has: it is private until the holder shows it, it carries a key (section 3.6.1), and it can name the genetic records the document concerns.

**The fingerprint rules do not change**, exactly as in section 11.8. A record that carries a field set takes the commitment of section 4.5 as its content hash (section 3.6.1, "With a field set").

**Committed fields.** Exactly these, every one present except the optional ones, none other:

| Field        | What it holds                                                                                                              |
| ------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `profile`    | `veilcore/profile/document/v1`                                                                                             |
| `type`       | One of `permit`, `certificate-of-analysis`, `lab-report`, `contract`, `protocol`, `transport`, `invoice`, `other`          |
| `title`      | What the holder calls it. Not empty                                                                                        |
| `issuer`     | Who issued it, as written on it, or empty. The holder's statement                                                          |
| `reference`  | Its number (a permit, an invoice, a lot), or empty                                                                         |
| `issued`     | The date written on it, `YYYY-MM-DD`, a real date, or empty. The holder's statement                                       |
| `files`      | 1 to 20 files, each `{ name, sha256, size }`: a one-line name, not empty; the SHA-256 of its bytes, 64 lowercase hex characters; its size in bytes, a whole number from 0 to 2^53 - 1. No two with the same `sha256` |
| `about`      | At most 20 records it concerns, each `{ name }` and, when it is a record the holder logged, `recordId`. Not parents         |
| `holder`     | Who holds and seals it. Not empty                                                                                          |
| `notes`      | Free text, or empty                                                                                                        |
| `loggedAt`   | When it was sealed, milliseconds since 1970 by the sealing device's clock, a whole number                                  |
| `nonce`      | 32 to 64 random bytes, lowercase hex (section 4.3)                                                                         |
| `keyBinding` | Optional, as in section 3.6.1                                                                                              |
| `fieldSchema`, `fieldSetRoot` | Optional, both or neither: a field set of the numbers printed on the document (section 4.5), such as a certificate's results under a published schema |

**Canonical form.** As in section 11.8: a value in any other form shall be refused, never tidied. The one-line fields (`title`, `issuer`, `reference`, `holder`, a file's `name`, an `about` entry's `name`) are text of at most 200 characters, with no control character and no white space at either end. `notes` is at most 20,000 characters. An `about` entry with an empty name and no `recordId` shall be refused.

**`about` is not `parents`.** A document descends from nothing. A verifier shall not treat an `about` entry as declared descent (section 3.4), and an obligation on a genetic record (section 3.5) does not ride to a document that names it.

**Checking a file against it.** A SHA-256 the holder merely states is a file's establishes nothing: it could be stated after the date. A verifier therefore checks a file against the record's committed fields themselves: recompute the record's fingerprint from them (sections 3.6.1, 4.4), establish the date of that fingerprint (sections 5 and 7), compute the SHA-256 of the file presented, and accept it only if it equals one of `files[].sha256`. The VeilCore web application carries the committed fields after the `#` of a link (`/check-document#d=`, base64url of `{"v":1,"fields":{...}}`), which a browser does not send to any server; an evidence bundle (section 8) carries them too. Sharing them shows every committed field, including `notes` and the names in `about`; it never shows the file.

**What a document record is offered.** The dated record and its key, the check above, the evidence bundle, and, when it carries a field set, the claims of section 4.5 about the numbers sealed with it: a certificate's holder can prove that one result is at most or at least a bound, or is a stated value, without showing the others or the certificate. Such a claim proves what the holder sealed, not that a laboratory measured it, unless a laboratory attests the record (section 4.5). **Not offered:** a DNA report, laboratory receipts and reports, agreements, descent. Those concern genetics; a document points at genetics through `about`.

**What it does not establish.** Everything in section 9.3 holds. A document record establishes that a file with exactly these bytes was in the holder's hands by the record's date. It does not establish that the document is genuine, that the named issuer issued it, or that what it says is true; nor that no other version existed. It does rule out a version made after the date being passed off as the earlier one.

**Vectors.** `document-v1.json` gives records under this profile and fields that shall be refused. It is checked by the VeilCore web application, the VeilCore registry, and the TypeScript and Python implementations here. Like the other profiles' vectors, it is outside the 100 record-format vectors of section 10.


## 11.12 - Laboratory results, version 2

**A draft (7 November 2026; revised 8 November 2026: the laboratory's name binding is salted, below; revised 12 November 2026: a `viability` kind, for a sample taken before or after a kill step, below).** This section defines how a laboratory signs a result bound to the record its sample came from: `veilcore/lab-result/v2`. It adds no envelope field and no commitment algorithm, and changes no profile: a version 2 result is a document record (section 11.11) under the document profile version 1, with a field set (section 4.5), signed by the laboratory over its record commitment exactly as section 4.5 says. The record format version is unchanged. Results made before this ("version 1": a document record of numbers a laboratory signed, naming the material only by name) keep checking exactly as they did.

**Why a second version.** A version 1 result names what was tested only by a name the laboratory typed. The link from the numbers to a record lived outside what the laboratory signed, in a registry's attestation, so a reader holding only the signed record could not tell which sample, which method or which panel the numbers came from. A result that is argued about is argued about a stated method on a stated sample; a format that does not carry them leaves the argument nothing to be about.

**The result statement.** A JSON object, serialised canonically (section 4.4), with exactly these fields and no others:

| Field | What it holds |
| --- | --- |
| `format` | `veilcore/lab-result/v2` |
| `kind` | One of `numbers`, `pathogen`, `match`, `lineage`, `dna-mark`, `viability`, `retraction` |
| `subject` | The proof code of the record the sender named for the sample, 64 lowercase hex characters (section 3.6.1: its fingerprint). That the sample came from that record's material is the sender's word, unless a custody record shows more |
| `sampleId` | The sample's identifier as the sender gave it. One line |
| `accession` | The laboratory's own accession number for the sample. One line |
| `method` | `{ id, version }`: the method or standard operating procedure, and its version. Each one line |
| `panel` | Optional. `{ id, version }`: the marker panel, and its version |
| `tested` | The date tested, `YYYY-MM-DD`, a real date. For a `viability` result, the date the result was read, at the end of incubation |
| `received` | Optional. The date received, a real date not after `tested` |
| `qc` | Optional. 1 to 12 `{ name, value }`, each one line of at most 60 characters, names not repeated: run and quality-control details as the laboratory reports them (a Ct cut-off, the limit of detection, an internal control's Ct, whether the positive, negative and no-template controls passed, a call rate, the run ID, the instrument). An empty list shall be omitted, not written |
| `result` | What was found, by kind (below). Absent for `retraction` and only for it |
| `replaces` | Optional. `{ result, reason }`: the code of an earlier result of the same laboratory (below) and why it is replaced, one of `re-test`, `correction`, `retraction`. A `retraction` result shall carry it with the reason `retraction`, and no other kind shall give that reason |
| `bindingSalt` | Optional in form, made for every result: 32 bytes from a cryptographically secure generator, 64 lowercase hex characters, not all one byte value, never reused. The salt of the laboratory's name binding (below). A result without it is still what its laboratory signed, but no binding names its laboratory |

A one-line field is text of at most 200 characters unless stated, not empty, with no control character, no format character (Unicode category Cf: bidirectional controls, zero-width spaces) and no white space at either end. Format characters are refused because two values that look the same must be the same. Text is NFC-normalised by the canonical serialisation, so one result written in two normal forms is one statement.

**Results, by kind.** Every proof code is 64 lowercase hex characters. Counts are whole numbers from 0 to 10^9 written as JSON numbers; `compared` is at least 1.

- `numbers`: `{ form }`, the id of a published field schema (section 4.5) other than the five below. The numbers are the field set's, under that form; the laboratory types them from its report.
- `pathogen`: `{ target, sampleType, detected, ct? }`: what was tested for (a viroid such as HLVd, a virus, a bacterium) and the kind of sample, both one line; `detected` true or false; `ct`, the cycle threshold, as text: a decimal under 100 with at most two places (`31.5`).
- `match`: `{ other, otherSampleId?, matches, compared?, differing? }`: the proof code the other sample was sent under, not the subject; that sample's ID, one line; whether the two samples gave the same calls at the markers compared, within the laboratory's own rule; markers compared and differing, `differing` not more than `compared`. A match says nothing about markers not compared, and does not say the two are the same plant, animal or variety.
- `lineage`: `{ parents, consistent, compared?, conflicts? }`: the proof codes of one or two parents, each once and neither the subject; whether the sample is consistent with descent from them; markers compared; conflicts with each parent, in the order named, one per parent, none more than `compared`.
- `dna-mark`: `{ seal, found, label? }`: a DNA mark, sealed (below); whether it was found in the sample; the laboratory's own name for the mark, one line, never its sequence (a label containing ten or more of `A`, `C`, `G`, `T` in a row, in either case, shall be refused).
- `viability`: a test for viable organisms in a sample taken before or after a kill step; its fields are under "Viability", below.
- `retraction`: no result.

**No genetic data is in a statement.** A comparison names records by proof code; neither the genotypes compared nor the calls are carried, and a verifier learns which records a laboratory compared and what it concluded, never on what genotype.

**Binding.** A version 2 result is a document record whose committed fields have `type` `lab-report`, `issued` equal to the statement's `tested`, `reference` equal to its `accession`, `issuer` equal to `holder` (both the laboratory's own name for itself, as it typed it; the name a verifier reports comes from the laboratory's binding, never from these fields), `about` exactly one entry naming its `sampleId` (with no `recordId`), a field set, and among `files` exactly one entry named `lab-result.json` whose `sha256` and `size` are those of the statement's canonical bytes. Other entries may name the laboratory's report file. The field set is under the kind's call form:

| `kind` | Form | Slots |
| --- | --- | --- |
| `numbers` | the statement's `form` | as that form says |
| `pathogen` | `veilcore/schema/pathogen/v1` | 0: 1 detected, 0 not; 1: `ct` times 100, when given |
| `match` | `veilcore/schema/genetic-match/v1` | 0: 1 match, 0 not; 1: `compared`; 2: `differing` |
| `lineage` | `veilcore/schema/lineage-check/v1` | 0: 1 consistent, 0 excluded; 1: `compared`; 2 and 3: conflicts with the first and second parent |
| `dna-mark` | `veilcore/schema/dna-mark/v1` | 0: 1 found, 0 not |
| `viability` | `veilcore/schema/viability/v1` | 0: 1 viable organisms recovered, 0 none recovered; 1: 0 before the kill step, 1 after it |
| `retraction` | `veilcore/schema/lab-retraction/v1` | 0: always 1 |

For every kind but `numbers` the field set's values shall be exactly those the statement gives: a slot is present if and only if the statement has the value. The forms are published with this specification (`profiles/fields/`); their ids are computed as section 4.5 says.

Because the statement's hash is a committed file entry, the laboratory's signature over the record commitment covers the statement; because the call is in the field set too, a holder can prove one value on a ledger (section 4.5: "not detected", "consistent", "0 differing") without showing the statement, and a verifier who is shown the statement checks that the two agree.

**What a ledger claim on a result shows.** A claim on a result's field set (section 4.5) shows the call and the counts only: "not detected", "same genotype", "consistent". It does not show what was tested for, which record was compared or which parents were named; those are in the statement, which the holder may show beside the claim. A verifier given the statement checks that its record commitment is the one the claim names. A verifier shall not report what was tested for or compared from a claim alone. A claim that a `viability` result recovered none shows neither the method, the medium, the incubation, the portion tested nor the limit of detection, and none recovered means nothing without them; a claim on its call alone does not show either whether the sample was taken before or after the kill step (the stage is the field set's other value, which the claim shows only if the holder proves it too). A verifier reporting such a claim shall say that these are in the statement, and shall not report the stage unless the claim shows it.

**What a verifier shall check.** (1) The statement is in its form. (2) The record's committed fields are a document record in the profile's form and the statement binds to them as above. (3) The field set's values make its root, the record's commitment is computed as section 4.5 says, and the laboratory's signature over that commitment verifies (section 4.5, the `attested` claim). (4) `subject`, `other` and `parents` are proof codes of records the verifier dates by their own anchors; the result says nothing about when they were made. (5) Which key is which laboratory is the verifier's decision (section 7); a name binding the laboratory publishes on the result (below) is evidence of that, not proof, and withdrawing it withdraws the laboratory's name from the result.

**The laboratory's name binding.** A laboratory names itself on a result by publishing, under the identity a registry knows it by, a value that ties its signing key to the result and to the record tested:

`nameBinding = hex(SHA-256("veilcore:lab-result-binding:v2:salted" || 0x00 || key || subject || bindingSalt))`

where `key` is the laboratory's signing key as the result file carries it (the point's x then y, 32 bytes each, big-endian: 64 bytes), and `subject` and `bindingSalt` are the statement's, 32 bytes each. On the reference registry it is an attestation by the laboratory's registered key, about the result's code, whose document hash is `nameBinding`; the registry serves it to anyone who asks about that code. A verifier holding the statement recomputes `nameBinding` and reports the laboratory's name only when a binding by one registered laboratory, not withdrawn, carries it. A holder who shows a claim on the result (section 4.5) without the statement may disclose `subject` and `bindingSalt` with it, and the verifier checks them the same way; the binding is then the laboratory's word for which record the claim is about. A statement without `bindingSalt` has no name binding: a verifier reports its key and never a laboratory's name for it.

**Why the binding is salted.** Nothing else in it is secret. The key is in every result file and on the ledger with every claim that names the result; the result's code is the binding's own subject and is published by any claim on it; proof codes are handed to every checker and every laboratory a sample goes to. Before this revision the binding was `SHA-256("veilcore:lab-result-binding:v2" || 0x00 || key || subject)`: anyone with a laboratory's key, a result's code and a list of proof codes could hash each code and see which one the laboratory tested, and a registry, or anyone with a copy of its attestations, could do that for every result of every laboratory, learning whose samples each laboratory handled. With 256 bits the laboratory and the holder share and nobody else has, the value tests nothing: guessing the subject means guessing the salt too. The salt is one per result, so a salt a holder discloses links that result only, which the statement it came with already names. It is in the statement, so it is covered by the laboratory's signature, travels wherever the statement goes, and needs no other copy kept or backed up. The subject stays in the binding, rather than being dropped, so that a claim shown without the statement can still be tied, by the laboratory and not by the holder, to the record it is about. **A binding of the earlier, unsalted form shall not be read**, so no implementation has a reason to publish one. Results signed under the earlier text of this draft carry no `bindingSalt`: they still check as signed, by their key, without a laboratory's name; a laboratory that wants its name on one signs it again (a `correction`). Their unsalted bindings stay where they were published, since a withdrawn attestation is still served; this revision stops new links, it does not take back old ones.

**What the name binding does not hide.** That a laboratory signed a result: the binding is under the laboratory's own identity. Nor any link made outside this format: on the reference application, a sample sent through its delivery flow also carries the laboratory's signature on the report, about the record (as in version 1), and the delivery itself is known to the registry that carried it.

**Replacing.** A result's code is its record commitment (section 4.5), the value its laboratory signed. A later result names an earlier one in `replaces`. A verifier shall treat the earlier result as replaced (or, for the reason `retraction`, withdrawn) only when both are signed by the same key, both name the same `subject`, the replacing result's `tested` is not before the earlier one's, and the earlier result does not itself name the replacing one (two results naming each other replace neither); a result that fails any of these changes nothing about the one it names. A replaced result is still what the laboratory signed: a verifier shall report it as replaced, not as unsigned. Nothing in this format tells a verifier holding only the earlier result that a later one exists: a verifier should look for one where the laboratory publishes them, and shall report a result it holds as signed, not as current.

**Viability: a sample before or after a kill step.** A producer that must not let a live culture leave its site (a fermentation's dried biomass sold as feed, an inactivated vaccine or cell line, heat-treated seed, a sterilised substrate) applies a kill step, a heat treatment, an inactivation or a sterilisation, and has a laboratory test samples taken before and after it for viable organisms. The laboratory reports what a microbiology report holds: which batch and which portion, the medium or media, how long and at what temperature each was incubated, the limit of detection, whether anything grew and, when the method counts, how much, and that the controls behaved (a plate count or bioburden count, as ISO 11737-1 describes, for a sample before the kill step; a sterility test, as USP <71> and ISO 11737-2 describe, or an enrichment culture, for a sample after it). A `viability` result is `{ batch, stage, killStep?, before?, strain, sampled, target, portion, cultures, lod, detected, count?, controls }`:

| Field | What it holds |
| --- | --- |
| `batch` | The batch or lot the sample was taken from, as the sender names it. One line |
| `stage` | `before` or `after`: whether the sample was taken before or after the kill step |
| `killStep` | The kill step's method and parameters as the sender states them ("steam, 95 °C core for 30 min"). One line. Present for an `after` sample, and only for it |
| `before` | Optional, for an `after` sample only: the code of the result for the same batch's `before` sample (below) |
| `strain` | The proof code of the strain or line record (section 11.9) the batch was made from. It may be `subject`, when the sample was sent under the strain record itself |
| `sampled` | The date the sample was taken, a real date, not after `received` (when given) or `tested` |
| `target` | What the test recovers, one line ("the production strain", "total yeasts and moulds", "any viable organism") |
| `portion` | The portion tested and its amount, one line ("25 g of meal in 225 mL broth", "10 units") |
| `cultures` | 1 to 4 `{ medium, time, temperature }`: each medium, and how long and at what temperature it was incubated, as the report states them. `medium` is one line; `time` and `temperature` are one line of at most 60 characters ("7 days", "25 °C"). No two the same |
| `lod` | `{ value, unit }`: the limit of detection. `value` is a decimal above 0; `unit` is one line of at most 60 characters ("CFU/g", "CFU per 25 g") |
| `detected` | `true` when viable organisms were recovered, `false` when none were |
| `count` | `{ value, unit }`, in the same form as `lod`: what was recovered, as reported. Optional when `detected` is `true` (an enrichment or presence/absence test reports growth and no count), and when given its `value` is above 0; absent when `detected` is `false`. A report gives a result below its limit of detection as "< 1 CFU per 25 g" or "not detected in 25 g", never as 0, and so does this format: the limit of detection says it |
| `controls` | `{ positive, positiveGrew, negativeGrew? }`: what the positive control was, one line ("the production strain, about 50 CFU, in killed meal"); `positiveGrew`, which shall be `true`; and, when a negative control was run, `negativeGrew`, which shall be `false` |

A decimal is written as a report prints it, with no sign and no exponent: 1 to 15 digits, no leading zero unless it is the only one, and optionally a point and 1 to 6 digits. A value in any other form shall be refused, never tidied: "1,000", "1.000,5" and "1 000" are refused, not read as a thousand or as one, and a form that takes a number from a person shall refuse them too and say how to type it. In `lod` and `count`, a value whose whole part is not 0, followed by a point and exactly 3 digits ("1.000", "12.500", "1234.567", "1000.000"), shall be refused as well: German, French and Spanish write the point between thousands, so a reader there takes "1.000 CFU/g" for a thousand and "1000.000 CFU/g" for a million. Written as "1", "1.0", "1000" or "1234.5670", the value is plain in every language; "1.5" and "2.25" stand. A whole part of 0 stands too ("0.125"): a thousands group never starts with 0, so nobody writes 125 as "0.125", and if a reader did misread it, the number would only look bigger, which makes a limit of detection look less sensitive and a count look worse, never better. **A run whose positive control did not grow, or whose negative control grew, shall not be signed:** it says nothing about the sample, and a format that could carry it would let "none recovered" stand on a test that could not have recovered anything. Under USP <71>, growth in the negative control makes a sterility test invalid; a positive control that does not grow is a separate failure, of the growth promotion or method suitability test, after which the medium or method may not be used for the test at all. Either way there is no result to sign. The laboratory tests again and signs the repeat. Other run details (the medium's lot, its growth promotion, a neutraliser, the method suitability test) go in `qc`.

**The pair.** An `after` result may name, in `before`, the result for the same batch's `before` sample. A verifier shall report an `after` result as paired with the result it names only when it holds both, both are signed by the same key, the named result is a `viability` result at stage `before`, both name the same `batch`, the same `strain` and the same `target`, the `before` sample was not taken after the `after` sample (`sampled`), and neither result is replaced or withdrawn (under "Replacing", above) by a result the verifier holds, the two results themselves included (an `after` result that also replaces the `before` result it names breaks the pair). A verifier holding a result that replaces or withdraws either one shall report that the pair does not stand, and which of the two was replaced or withdrawn; neither is then evidence about the other. When both results name the same `method`, the pair is the same laboratory's evidence that the batch carried something its method recovered before the kill step. When they name different methods, a verifier shall say so: the pair then shows only that the batch carried something the laboratory recovered before the kill step, not that the `after` sample's method recovers it from this material. Neither shows that the `after` method could recover the organism from treated material; that is shown by the `after` run's own positive control, ideally the organism added to killed product (method suitability), which `controls.positive` names. A pair is read as it is: when the `before` sample recovered none, whatever the `after` sample shows, the pair does not show that the kill step changed anything, and a verifier shall say so. A named result that fails any of these changes nothing about the `after` result, which is still what its laboratory signed.

**The strain, without showing it.** `strain` names the strain record by its proof code only. Whoever holds the statement can tie the batch to that record, and date the record by its own anchors; nothing of the record's contents is in the statement, and the proof code is a salted commitment (section 4.3) that tells nobody which strain it is. A claim on the result's field set shows neither. A holder who does not want a buyer to tie batches to one record across results shows the buyer the claim and not the statement. A holder who hands out several results should know what they show together: every one names the same `strain`, so whoever holds two ties both batches to one strain record; the `batch` names and the laboratory's `accession` numbers, read in order with their dates, show how often the holder produces and roughly how much; and every ledger claim on a result shows the laboratory's key and the claim's date, so the number and timing of claims made on one laboratory's results are public.

**What a viability result does not establish.** That the batch is dead, sterile or free of the strain. A test recovers only what grows on its media, in its time and at its temperature, from the portion tested, above its limit of detection: organisms injured but not killed, dormant (spores), or needing other conditions may not grow, and a portion may not represent its batch. USP <71> says the same of its own test: a satisfactory result shows only that no contaminating organism was found in the sample under the test conditions. Nor that the sample came from the batch named, or the batch from the strain named (the sender's word, unless a custody record shows more); nor that what left a site was the batch tested. A verifier shall report "no viable organisms recovered from {portion}, under {method}, below the limit of detection of {lod}" (or "< {lod}"), never "sterile", "dead", "proves" or a count of 0.

**DNA marks.** A mark is a sequence a laboratory wrote into a line, or found in it, to recognise it later. Its sequence is the line's holder's and the laboratory's secret: it is sealed, never published, and shown only to settle a dispute.

`seal = hex(SHA-256("veilcore:dnamark:v1" || 0x00 || salt || sequence))`

where `salt` is 32 bytes from a cryptographically secure generator and `sequence` is the mark in ASCII: 10 to 100,000 of the letters `A`, `C`, `G` and `T`, upper case, nothing else. A sequence in any other form shall be refused rather than tidied. The salt keeps a seal from being matched against a list of known marks. Whoever holds the sequence and the salt (an "opening") can show that a result sealed that mark; anyone shown the opening recomputes the seal. A seal shows that the laboratory recorded a mark by the result's date; it does not show that the mark is unique, that the laboratory put it there, or that a line carrying it descends from this one.

**What a version 2 result does not establish.** Everything in sections 9.3 and 11.11 holds. The format records what a laboratory signed, about which sample, by which method; it does not establish that the method was sound, that the sample came from the subject's material, that a match means identity, that consistency means descent or that none recovered means a batch is dead, or that a result is the laboratory's latest. **The issuer of this format tests no sample, does not mark DNA, and vouches for no result.**

**Vectors.** `conformance/lab-result-v2.json` gives statements and their file entries (20), statements that shall be refused (70), statements bound and not bound to records (33), mark seals and refusals (8), name bindings and refusals (7), and viability pairs that pair and that do not, with the results the verifier holds beside them (20): 158 in all, computed by `conformance/lab-result-vectors.mjs` from this section with `node:crypto` and the canonicaliser only. The TypeScript and Python implementations here and the VeilCore web application pass them. They are not part of the record format: an implementation that does not offer laboratory results leaves them out (`--without-lab-results`) and says so.

## 12 - What is not yet specified

Named so that implementers do not mistake absence for oversight.

**Per-field commitments** are now specified for up to sixteen values per record (section 4.5). Two things remain open. The sixteen-slot bound is a cost, not a principle: a wider set is a slower proof, and a later algorithm identifier may raise it. And **the shape does not fit every kind of evidence**: where a determination rests on statistical distance across hundreds or thousands of values, committing each as a leaf is the wrong instrument at any width, and what would be attested is a laboratory's computation rather than each value it ran over.

**Semantic conformance.** The vectors in section 10 establish that two implementations compute identical commitments and fold identical proofs for the same inputs. They do not test whether a field's contents are permissible - the restriction on `payee` in section 3.5 is the first such rule. A conformance profile covering field content is not specified here, and should be defined against a requiring body's audit needs rather than guessed at in advance.

---

## 13 - Comment

This document is published for comment, and specific correction is more useful than general agreement. The classification table in section 6.2 is the part most in need of review by people who adjudicate disputes in a given domain; the authors' assignments there are reasoned but not authoritative.

**Implementations:** TypeScript (reference, published under Apache 2.0 with the conformance vectors), Python, and Rust. All three pass the same vectors.

**Contact:** Hunter Roberts, VeilCore - hunter@veilcore.org

---

*This specification describes a format, not a service. Every property it claims is either demonstrable from the published implementations and vectors, or is stated as a limitation. Where the authors have made a judgement rather than followed a constraint - the field classification in section 6.2 above all - that is marked as such.*
