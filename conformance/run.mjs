// Conformance runner.
//
// Point this at any implementation of the VeilCore record format and it reports whether
// that implementation is conformant. Certification is impossible without it — you
// cannot certify conformance you cannot test.
//
//   node conformance/run.mjs                    test the reference implementation
//   node conformance/run.mjs ./path/to/impl.mjs test another implementation
//
// An implementation must export `canonicalise(value)` and `computeCommitment(record)`;
// the later sections fail, not skip, when it does not export what they test.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';

const target = process.argv[2] ?? '../dist/index.js';
const impl = await import(target.startsWith('.') ? new URL(target, import.meta.url).href : target);
const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));

let pass = 0;
let fail = 0;
const failures = [];

const check = (section, name, expected, actual) => {
  if (expected === actual) { pass++; return; }
  fail++;
  failures.push({ section, name, expected, actual });
};

console.log(`VeilCore conformance — format ${vectors.formatVersion}`);
console.log(`target: ${target}\n`);

if (typeof impl.canonicalise !== 'function') {
  console.error('FAIL: implementation does not export canonicalise()');
  process.exit(1);
}
if (typeof impl.computeCommitment !== 'function') {
  console.error('FAIL: implementation does not export computeCommitment()');
  process.exit(1);
}

console.log('Canonicalisation');
for (const v of vectors.canonicalisation) {
  let actual;
  try { actual = impl.canonicalise(v.inputText !== undefined ? JSON.parse(v.inputText) : v.input); } catch (e) { actual = `threw: ${e.message}`; }
  check('canonicalisation', v.name, v.expected, actual);
  console.log(`  ${v.expected === actual ? 'PASS' : 'FAIL'}  ${v.name}`);
}

console.log('\nCommitments');
for (const v of vectors.commitments) {
  let actual;
  try { actual = await impl.computeCommitment(v.record); } catch (e) { actual = `threw: ${e.message}`; }
  check('commitment', v.name, v.expectedCommitment, actual);
  console.log(`  ${v.expectedCommitment === actual ? 'PASS' : 'FAIL'}  ${v.name}`);
}

// Rejections. A suite that only tests valid input cannot catch two implementations
// disagreeing about what is INVALID, which is where every divergence found in the
// August 2026 external review actually lived.
console.log('\nRejections');
for (const v of vectors.rejections ?? []) {
  let rejected = false;
  try {
    impl.canonicalise(v.inputText !== undefined ? JSON.parse(v.inputText) : v.input);
  } catch {
    rejected = true;
  }
  check('rejections', v.name, 'rejected', rejected ? 'rejected' : 'accepted');
  console.log(`  ${rejected ? 'PASS' : 'FAIL'}  ${v.name}`);
}

// Attestation payloads. The bytes an attester signs. An implementation that builds
// these differently disagrees about what a signature protects, and until these
// vectors existed nothing asked — the TypeScript payload signed the attester's key
// and left displayName, role and accreditation outside it.
if (vectors.attestations?.length) {
  console.log('\nAttestation payloads');
  if (typeof impl.attestationPayload !== 'function') {
    // Not exposing it fails rather than skipping. A missing check that reports
    // nothing is how the inclusion vectors went unrun for weeks.
    fail += vectors.attestations.length;
    failures.push(['attestations', 'attestationPayload not exposed by this implementation', 'a function', 'nothing']);
    console.log('  FAIL  attestationPayload not exposed');
  } else {
    for (const v of vectors.attestations) {
      let actual;
      try { actual = await impl.attestationPayload(v.attestation); }
      catch (e) { actual = `threw: ${e.message}`; }
      check('attestations', v.name, v.expectedPayload, actual);
      console.log(`  ${v.expectedPayload === actual ? 'PASS' : 'FAIL'}  ${v.name}`);
    }
  }
}

// Inclusion proofs. Not run at all until now: this runner reported "Conformant"
// without ever folding a path.
if (vectors.inclusion?.length) {
  console.log('\nInclusion proofs');
  if (typeof impl.verifyInclusion !== 'function') {
    console.error('  implementation does not export verifyInclusion()');
    fail += vectors.inclusion.length;
  } else {
    for (const v of vectors.inclusion) {
      // The vector is a fold: commitment plus path should produce expectedRoot.
      // verifyInclusion folds and compares, so a proof naming the expected root
      // verifies only if the fold agrees with it.
      let actual;
      try {
        actual = (await impl.verifyInclusion({
          commitment: v.commitment,
          path: v.path,
          root: v.expectedRoot,
        })) ? 'folds to the stated root' : 'does not fold to the stated root';
      } catch (e) { actual = `threw: ${e.message}`; }
      check('inclusion', v.name, 'folds to the stated root', actual);
      console.log(`  ${actual === 'folds to the stated root' ? 'PASS' : 'FAIL'}  ${v.name}`);
    }
  }
}

// Field sets (SPEC 4.5). Compared as the JSON of the summary: schema id, the 32-byte slot
// values, salts, the 16 leaves and the set root, in that order.
if (vectors.fieldSets?.length || vectors.fieldRejections?.length || vectors.commitmentRejections?.length) {
  console.log('\nField sets');
  const has = typeof impl.fieldSetSummary === 'function';
  if (!has) {
    console.error('  implementation does not export fieldSetSummary()');
    fail += (vectors.fieldSets?.length ?? 0) + (vectors.fieldRejections?.length ?? 0);
  } else {
    for (const v of vectors.fieldSets ?? []) {
      let actual;
      try { actual = JSON.stringify(await impl.fieldSetSummary(v.input)); } catch (e) { actual = `threw: ${e.message}`; }
      const expected = JSON.stringify(v.expected);
      check('fieldSets', v.name, expected, actual);
      console.log(`  ${expected === actual ? 'PASS' : 'FAIL'}  ${v.name}`);
    }
    for (const v of vectors.fieldRejections ?? []) {
      let actual = 'accepted';
      try { await impl.fieldSetSummary(v.input); } catch { actual = 'refused'; }
      check('fieldRejections', v.name, 'refused', actual);
      console.log(`  ${actual === 'refused' ? 'PASS' : 'FAIL'}  refuses: ${v.name}`);
    }
  }
  for (const v of vectors.commitmentRejections ?? []) {
    let actual = 'accepted';
    try { await impl.computeCommitment(v.record); } catch { actual = 'refused'; }
    check('commitmentRejections', v.name, 'refused', actual);
    console.log(`  ${actual === 'refused' ? 'PASS' : 'FAIL'}  refuses: ${v.name}`);
  }
}

// Report pairings (SPEC 3.7): the value a ledger pairing publishes for a report.
if (vectors.pairings?.length) {
  console.log('\nReport pairings');
  if (typeof impl.dnaPairBinding !== 'function') {
    console.error('  implementation does not export dnaPairBinding()');
    fail += vectors.pairings.length;
    failures.push({ section: 'pairings', name: 'dnaPairBinding not exposed by this implementation', expected: 'a function', actual: 'nothing' });
  } else {
    for (const v of vectors.pairings) {
      let actual;
      try { actual = await impl.dnaPairBinding(v.input.reportHash, v.input.identity, v.input.salt); } catch (e) { actual = `threw: ${e.message}`; }
      check('pairings', v.name, v.expected, actual);
      console.log(`  ${v.expected === actual ? 'PASS' : 'FAIL'}  ${v.name}`);
    }
  }
}

// Records that name their own key (SPEC 3.6.1): the key from its secret, fingerprints old
// and new, whether a key matches a record, and the refusal of a malformed keyBinding.
const KEY_BOUND = ['keyBoundKeys', 'keyBoundRecords', 'keyBoundChecks', 'keyBoundRefusals'];
const keyBoundCount = KEY_BOUND.reduce((n, k) => n + (vectors[k]?.length ?? 0), 0);
if (keyBoundCount) {
  console.log('\nRecords that name their own key');
  const needed = ['identityFromSecret', 'keySaltOf', 'keyBindingOf', 'computeRecordFingerprint', 'keyMatchesRecord'];
  const missing = needed.filter((f) => typeof impl[f] !== 'function');
  if (missing.length) {
    console.error(`  implementation does not export ${missing.join(', ')}`);
    fail += keyBoundCount;
    failures.push({ section: 'keyBound', name: `${missing.join(', ')} not exposed by this implementation`, expected: 'functions', actual: 'nothing' });
  } else {
    const run = async (section, name, expected, f) => {
      let actual;
      try { actual = await f(); } catch (e) { actual = `threw: ${e.message}`; }
      check(section, name, expected, actual);
      console.log(`  ${expected === actual ? 'PASS' : 'FAIL'}  ${name}`);
    };
    for (const v of vectors.keyBoundKeys ?? []) {
      await run('keyBoundKeys', `the key from record secret ${v.recordSecret.slice(0, 8)}...`,
        JSON.stringify([v.identity, v.keySalt, v.keyBinding]),
        async () => JSON.stringify([
          await impl.identityFromSecret(v.recordSecret),
          await impl.keySaltOf(v.recordSecret),
          await impl.keyBindingOf(v.identity, v.keySalt),
        ]));
    }
    for (const v of vectors.keyBoundRecords ?? []) {
      await run('keyBoundRecords', v.name,
        JSON.stringify([v.canonical, v.algorithm, v.contentHash, v.fingerprint]),
        async () => {
          const r = await impl.computeRecordFingerprint(v.fields);
          return JSON.stringify([impl.canonicalise(v.fields), r.algorithm, r.contentHash, r.fingerprint]);
        });
    }
    for (const v of vectors.keyBoundChecks ?? []) {
      await run('keyBoundChecks', `${v.matches ? 'matches' : 'does not match'}: ${v.name}`,
        v.matches ? 'matches' : 'does not match',
        async () => ((await impl.keyMatchesRecord(v.identity, { fingerprint: v.fingerprint, keySalt: v.keySalt, contentHash: v.contentHash })) === true ? 'matches' : 'does not match'));
    }
    for (const v of vectors.keyBoundRefusals ?? []) {
      let actual = 'accepted';
      try { await impl.computeRecordFingerprint(v.fields); } catch { actual = 'refused'; }
      check('keyBoundRefusals', v.name, 'refused', actual);
      console.log(`  ${actual === 'refused' ? 'PASS' : 'FAIL'}  refuses: ${v.name}`);
    }
  }
}

// Animal records (SPEC 11.8, draft): the profile's form, and fingerprints computed exactly as
// any record's. A record is checked through computeAnimalRecordFingerprint, which refuses
// fields not in the profile's form; a refusal vector must be refused by it.
const animalCount = (vectors.animalRecords?.length ?? 0) + (vectors.animalRefusals?.length ?? 0);
if (animalCount) {
  console.log('\nAnimal records');
  if (typeof impl.computeAnimalRecordFingerprint !== 'function') {
    console.error('  implementation does not export computeAnimalRecordFingerprint()');
    fail += animalCount;
    failures.push({ section: 'animal', name: 'computeAnimalRecordFingerprint not exposed by this implementation', expected: 'a function', actual: 'nothing' });
  } else {
    for (const v of vectors.animalRecords ?? []) {
      let actual;
      try {
        const r = await impl.computeAnimalRecordFingerprint(v.fields);
        actual = JSON.stringify([impl.canonicalise(v.fields), r.algorithm, r.contentHash, r.fingerprint]);
      } catch (e) { actual = `threw: ${e.message}`; }
      const expected = JSON.stringify([v.canonical, v.algorithm, v.contentHash, v.fingerprint]);
      check('animalRecords', v.name, expected, actual);
      console.log(`  ${expected === actual ? 'PASS' : 'FAIL'}  ${v.name}`);
    }
    for (const v of vectors.animalRefusals ?? []) {
      let actual = 'accepted';
      try { await impl.computeAnimalRecordFingerprint(v.fields); } catch { actual = 'refused'; }
      check('animalRefusals', v.name, 'refused', actual);
      console.log(`  ${actual === 'refused' ? 'PASS' : 'FAIL'}  refuses: ${v.name}`);
    }
  }
}

// Strain and line records (SPEC 11.9, draft): the profile's form, and fingerprints computed exactly as
// any record's. A record is checked through computeStrainRecordFingerprint, which refuses
// fields not in the profile's form; a refusal vector must be refused by it.
const strainCount = (vectors.strainRecords?.length ?? 0) + (vectors.strainRefusals?.length ?? 0);
if (strainCount) {
  console.log('\nStrain and line records');
  if (typeof impl.computeStrainRecordFingerprint !== 'function') {
    console.error('  implementation does not export computeStrainRecordFingerprint()');
    fail += strainCount;
    failures.push({ section: 'strain', name: 'computeStrainRecordFingerprint not exposed by this implementation', expected: 'a function', actual: 'nothing' });
  } else {
    for (const v of vectors.strainRecords ?? []) {
      let actual;
      try {
        const r = await impl.computeStrainRecordFingerprint(v.fields);
        actual = JSON.stringify([impl.canonicalise(v.fields), r.algorithm, r.contentHash, r.fingerprint]);
      } catch (e) { actual = `threw: ${e.message}`; }
      const expected = JSON.stringify([v.canonical, v.algorithm, v.contentHash, v.fingerprint]);
      check('strainRecords', v.name, expected, actual);
      console.log(`  ${expected === actual ? 'PASS' : 'FAIL'}  ${v.name}`);
    }
    for (const v of vectors.strainRefusals ?? []) {
      let actual = 'accepted';
      try { await impl.computeStrainRecordFingerprint(v.fields); } catch { actual = 'refused'; }
      check('strainRefusals', v.name, 'refused', actual);
      console.log(`  ${actual === 'refused' ? 'PASS' : 'FAIL'}  refuses: ${v.name}`);
    }
  }
}

console.log(`\n${pass} passed, ${fail} failed`);

if (fail > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`\n  ${f.section} — ${f.name}`);
    console.log(`    expected: ${f.expected}`);
    console.log(`    actual:   ${f.actual}`);
  }
  console.log('\nNot conformant.');
  process.exit(1);
}

console.log('\nConformant.');
