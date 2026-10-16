// Animal records (SPEC 11.8, draft).
//
// Every animal vector, in both entry points and in the Python implementation; the shared set
// carries exactly the published animal-individual-v1.json; the profile's form is checked and
// a refusal never becomes a fingerprint; plant records are untouched; and the profile JSON
// published under profiles/ names the same fields.
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as node from '../dist/index.js';
import * as browser from '../dist/index.browser.js';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const V = JSON.parse(readFileSync(here('../conformance/vectors.json'), 'utf8'));
const PUBLISHED = JSON.parse(readFileSync(here('../conformance/animal-individual-v1.json'), 'utf8'));
const PROFILE = JSON.parse(readFileSync(here('../profiles/animal-individual-v1.json'), 'utf8'));

test('the shared set carries the published animal vectors unchanged, and all of them', () => {
  assert.deepEqual(V.animalRecords, PUBLISHED.records);
  assert.deepEqual(V.animalRefusals, PUBLISHED.refusals);
  assert.equal(PUBLISHED.profile, node.ANIMAL_INDIVIDUAL_PROFILE);
  assert.ok(V.animalRecords.length >= 5 && V.animalRefusals.length >= 20);
  // Bound and unbound both: a set of only key-bound records tests half of it.
  assert.ok(V.animalRecords.some((r) => r.algorithm === 'sha256/key-bound/v1'));
  assert.ok(V.animalRecords.some((r) => r.algorithm === 'sha256/canonical-json/v1'));
});

for (const [entry, impl] of [['node', node], ['browser', browser]]) {
  test(`${entry}: every animal record: form, canonical text, content hash, fingerprint`, async () => {
    for (const v of V.animalRecords) {
      assert.deepEqual(impl.animalIndividualProblems(v.fields), [], v.name);
      assert.equal(impl.isAnimalIndividual(v.fields), true, v.name);
      assert.equal(impl.canonicalise(v.fields), v.canonical, v.name);
      const r = await impl.computeAnimalRecordFingerprint(v.fields);
      assert.deepEqual(r, { algorithm: v.algorithm, contentHash: v.contentHash, fingerprint: v.fingerprint }, v.name);
      // The profile changes no fingerprint rule: the plain function gives the same answer.
      assert.deepEqual(await impl.computeRecordFingerprint(v.fields), r, v.name);
      const ok = await impl.verifyRecordFingerprint({ fields: v.fields, fingerprint: v.fingerprint, algorithm: v.algorithm });
      assert.equal(ok.valid, true, v.name);
    }
  });

  test(`${entry}: every refusal is refused, with a reason, and never fingerprinted`, async () => {
    for (const v of V.animalRefusals) {
      const problems = impl.animalIndividualProblems(v.fields);
      assert.ok(problems.length > 0, v.name);
      assert.equal(impl.isAnimalIndividual(v.fields), false, v.name);
      await assert.rejects(impl.computeAnimalRecordFingerprint(v.fields), /not a valid animal record/, v.name);
    }
  });

  test(`${entry}: plant records are not animal records, and keep their fingerprints`, async () => {
    for (const v of V.keyBoundRecords) {
      assert.equal(impl.isAnimalIndividual(v.fields), false, v.name);
      assert.equal((await impl.computeRecordFingerprint(v.fields)).fingerprint, v.fingerprint, v.name);
    }
  });
}

test('the reasons are plain sentences a holder can act on', () => {
  const cow = V.animalRecords[1].fields;
  assert.deepEqual(node.animalIndividualProblems({ ...cow, sex: 'cow' }), ['sex must be female, male or unknown']);
  assert.deepEqual(node.animalIndividualProblems({ ...cow, idScheme: '' }), [
    'idScheme must say which ID scheme the individual ID belongs to',
  ]);
  assert.deepEqual(node.animalIndividualProblems({ ...cow, dateOfBirth: '2025-02-29' }), [
    'dateOfBirth must be empty or a date written YYYY-MM-DD',
  ]);
  assert.deepEqual(node.animalIndividualProblems({ ...cow, dateOfBirth: '2024-02-29' }), []);
  assert.deepEqual(node.animalIndividualProblems({ ...cow, name: 'Cow ' }), ['name must not start or end with a space']);
  assert.deepEqual(node.animalIndividualProblems(null), ['the fields must be an object']);
});

test('Python (conformance/impl.py) agrees on every animal record and refusal', () => {
  const ask = (op, input) => {
    try {
      return { ok: JSON.parse(execFileSync('python3', [here('../conformance/impl.py')], { input: JSON.stringify({ op, input }) }).toString()).result };
    } catch {
      return { refused: true };
    }
  };
  for (const v of V.animalRecords) {
    assert.deepEqual(ask('animalFingerprint', v.fields).ok, { algorithm: v.algorithm, contentHash: v.contentHash, fingerprint: v.fingerprint }, v.name);
  }
  for (const v of V.animalRefusals) assert.equal(ask('animalFingerprint', v.fields).refused, true, v.name);
  // The same edges the TypeScript tests name.
  const cow = V.animalRecords[1].fields;
  assert.equal(ask('animalFingerprint', { ...cow, dateOfBirth: '2024-02-29' }).refused, undefined);
  assert.equal(ask('animalFingerprint', { ...cow, name: 'Cow ' }).refused, true);
  assert.equal(ask('animalFingerprint', { ...cow, name: '﻿Cow' }).refused, true);
});

test('the published profile names exactly the committed fields, and the parent roles', () => {
  const S = PROFILE['x-veilcore'].sealedFields;
  const sealed = Object.keys(V.animalRecords[0].fields).sort();
  assert.deepEqual(Object.keys(S.properties).sort(), sealed);
  assert.deepEqual([...S.required].sort(), sealed.filter((k) => k !== 'keyBinding'));
  assert.equal(S.additionalProperties, false);
  assert.deepEqual(PROFILE['x-veilcore'].parentRoles, ['sire', 'dam']);
  assert.equal(PROFILE.$id, node.ANIMAL_INDIVIDUAL_PROFILE);
});
