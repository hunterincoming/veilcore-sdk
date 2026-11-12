# Changelog

Versions before 0.16.0 are described in their commit messages and on npm.

## Unreleased

- **Laboratory results v2: a `viability` kind (SPEC 11.12, draft).** A laboratory signs a test for
  viable organisms in a sample taken before or after a kill step (a heat treatment, an
  inactivation, a sterilisation): the batch, the stage, the kill step's method and parameters, the
  portion tested, each medium with its incubation time and temperature, the limit of detection,
  whether anything was recovered and how much, and the controls. A run whose positive control did
  not grow, or whose negative control grew, can't be signed. The batch ties to the strain record it
  was made from by proof code only (`strain`), and an after-sample may name the result for its
  before-sample (`before`), which a verifier reads as a pair only under the rules of the section.
  The call and the stage are a new call form, `veilcore/schema/viability/v1`. The section says what
  it does not establish: none recovered is not dead or sterile. `labViabilityPairProblems`; 45 more
  vectors (133 in all); Python too; a new conformance op, `labViabilityPair`.
- **Laboratory results v2: the laboratory's name binding is salted (SPEC 11.12, draft).** The
  binding a laboratory publishes to name itself on a result was SHA-256 over a tag, its key and
  the tested record's proof code. The key is in every result file and the result's code is the
  binding's own subject, so anyone with a list of proof codes could hash each one and see which
  record a laboratory tested, and a registry could do it for all of them. The binding now also
  covers `bindingSalt`, 32 random bytes per result carried in the statement (so the laboratory's
  signature covers it and it travels with the result), and has its own tag. A holder shows the
  salt with the result or beside a claim; without it the binding tests nothing. Bindings of the
  earlier form are not read. Statements without the salt (signed under the earlier text of this
  draft) still check as signed, without a laboratory's name. `labNameBinding`; 12 more
  vectors (88 in all: a salted statement, four salt refusals, four name bindings, three
  refusals); Python too.
- **Laboratory results, version 2 (SPEC 11.12, draft).** A laboratory signs a result bound to the
  record its sample came from: a result statement (the record's proof code, the sample ID, the
  laboratory's accession number, the method and panel with their versions, QC figures, the
  dates, the call, and an optional earlier result it replaces, with a re-test, correction or
  retraction reason) sealed into the signed document record as a file entry, with the call in a
  field set so a holder can prove it on a ledger. Kinds: numbers under a form, pathogen or viroid
  tests, a comparison with another record and a parentage check (both by proof code only, no
  genotype), a sealed DNA mark (shown only in a dispute), and a withdrawal. `labStatementProblems`,
  `labStatementFile`, `labBindingProblems`, `labCallValues` and `dnaMarkSeal`; the five call forms
  in `profiles/fields/`, with the seed-quality form the web application publishes (the `numbers` vectors seal under it, so the vectors need its document); 76 vectors (`conformance/lab-result-v2.json`, computed by
  `lab-result-vectors.mjs` from the section with node:crypto and the canonicaliser only); Python
  too; `--without-lab-results` for implementations that don't offer them. Version 1 results are
  unchanged.
- **Deal records: the same statement twice counts once.** Two statements that say exactly the
  same thing (every field but `at` and `statementId`, so the same period and content) are one
  statement, the first; a reply, payment or confirmation naming either counts for it, and the
  line notes the copy. One message saved twice is read once too: before, it made two lines and
  its amount was counted twice in `open`. A report sent again after a lost answer, signed with
  a new time, no longer doubles what is owed (SPEC 11.10). "The same" is exact: the canonical
  form without `from`, `at` and `statementId`; any other field counts, even one the checker
  doesn't read. `test/fixtures/deal-record-copies.json` is the cross-check.
- **Deal records: the registry's order, and exact payments.** A record's messages are read in
  the order of the registry's `seq` saved beside each one, never the senders' signed times,
  which either side can set; `order` says which was used (an older record without `seq` falls
  back to signed times). A `paid` counts only once the statement is accepted, and settles it
  only when it is the full amount the statement leaves to pay (less the tax it declared), in
  its currency. Anything less is a short payment: `short` says what is still owed, and that
  stays in `open`, even if the short amount is confirmed received.
- **Strain and line records (SPEC 11.9): version 1 is final (3 November 2026).** No field
  changed; records made under the draft check exactly as before.
- **Field sets on records that name their key (SPEC 3.6.1).** `computeRecordFingerprint` takes
  fields with `fieldSchema` and `fieldSetRoot`: the content hash is then the SPEC 4.5
  commitment, so a claims-contract proof about that commitment is about the record. Eight more
  key-bound vectors (two records, two checks, four refusals); Python too. The Rust
  implementation needs the same change before it passes them.
- **Document records (SPEC 11.11, version 1 final on 31 October 2026).** `computeDocumentRecordFingerprint`,
  `documentProblems` and `isDocumentRecord`; `document_record_fingerprint` in Python; 36
  vectors (`conformance/document-v1.json`, from the web application) with
  `--without-document-profile` for implementations that don't check the profile. A document is
  sealed by each file's SHA-256, name and size; the file never is. `veilcore backup` checks a
  document record's form.
- **A document record may carry a field set** (`fieldSchema` and `fieldSetRoot`, both or neither):
  a certificate's numbers, sealed with it so one can be proved later (SPEC 4.5). SPEC 11.11 now
  lists the two fields and the claims a document is offered.
- **SPEC 11.8 says version 1 is final**, as decided on 16 October; the heading still said draft.
- **SPEC 11.8 and 11.9:** agreements are now offered for animal and strain records, each with
  terms of its own (`subject` in the terms).

## 0.18.1

- **Deal records:** `handon` and `handon-ask` (handing a license on to a new holder, with the
  licensor's approval) and `handon-off` (the licensor calling one off) are read and checked
  for the right sender. A signed message of a kind
  this version doesn't know is reported as unread, not as a failure, so newer records still
  check with an older tool.

## 0.18.0

- **Deal records (SPEC 11.10, a draft).** `checkDealRecord` and `veilcore deal <file>`: checks
  every signature in a license deal's record (or every deal in a backup), refuses messages from
  the wrong side, and totals what both sides signed as paid and received. Built for showing a
  royalty history to someone else, such as a lender. Says plainly what it cannot show: who
  holds the keys. `verifyEd25519`: the strict Ed25519 check the other verifiers use.

## 0.17.1

- Same code as 0.17.0, which was tagged but never reached npm. Releases are now staged on npm
  from CI with provenance and go live only when a maintainer approves them with 2FA
  (RELEASING.md).

## 0.17.0

- **`veilcore backup <file> [--out <folder>]`.** Opens a VeilCore web app backup file and
  checks every record in it with nothing from VeilCore: recomputes each record's fingerprint
  from the sealed fields the file carries, folds each inclusion proof to its batch root, and
  names the transaction that dates the root (to look up on any explorer; the tool doesn't go
  online). Opens password-locked files (version 4: PBKDF2-SHA256, AES-256-GCM); the password
  comes from `VEILCORE_BACKUP_PASSWORD` or is asked for. Keys in the file are never printed.
  Files saved before 23 October 2026 carry keys only, and it says so.
- **Strain and line records (SPEC 11.9, a draft).** The `strain` profile, for microbial strains,
  cell lines and insect lines: `strainProblems`, `isStrainRecord` and
  `computeStrainRecordFingerprint`; the Python implementation's `strain_record_fingerprint`.
  30 new vectors, copied unchanged from the web application's `strain-v1.json`: five records
  and 25 sets of fields the profile refuses. `veilcore backup` checks a strain record's form.
- 181 conformance vectors in all. TypeScript and Python pass all 181; the Rust implementation
  (veilcore-rs 0.4.0, unchanged) passes 131, leaving both profiles' 50 refusals to this package
  (`--without-animal-profile --without-strain-profile`).

## 0.16.0

Nothing about existing fingerprints changes: every record that verified under 0.15.0
verifies the same way.

- **Records that name their own key (SPEC 3.6.1).** `computeRecordFingerprint` and
  `verifyRecordFingerprint` give and check `sha256/key-bound/v1` fingerprints
  (`H("veilcore:v1:keyrecord", keyBinding, contentHash)`) for records that carry
  `keyBinding`, and the plain content hash for records that don't. `keyMatchesRecord`,
  `identityFromSecret`, `keySaltOf`, `keyBindingOf`, `keyBoundFingerprint` and
  `bindingForSecret` make and compare the pieces. 20 new vectors. Records sealed on
  veilcore.org since 14 October 2026 need this to check.
- **A report paired on a ledger (SPEC 3.7).** `dnaPairBinding` computes
  `H("veilcore:v1:dnapair", reportHash, identity, salt)`. 1 new vector.
- **Animal records (SPEC 11.8, a draft).** The `animal-individual-v1` profile:
  `animalIndividualProblems`, `isAnimalIndividual` and `computeAnimalRecordFingerprint`.
  30 new vectors: five animal records and 25 sets of fields the profile refuses.
- **SPEC 4.5, claims check 8:** a mask over every described slot is refused, and
  `supersedes` is matched beyond `recordId`.
- 151 conformance vectors in all (0.15.0 had 100). The Python implementation passes all
  151; the Rust implementation (veilcore-rs 0.4.0) passes 126, leaving the animal profile's
  25 refusals to this package.
- CI runs the tests and every vector, in TypeScript and Python, on every push and pull
  request.
