# Changelog

Versions before 0.16.0 are described in their commit messages and on npm.

## 0.18.1

- **Deal records:** `handon` and `handon-ask` (handing a license on to a new holder, with the
  licensor's approval) are read and checked for the right sender. A signed message of a kind
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
