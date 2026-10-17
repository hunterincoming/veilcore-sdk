# Changelog

Versions before 0.16.0 are described in their commit messages and on npm.

## 0.16.0 (unreleased)

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
