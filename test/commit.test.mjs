// The property everything rests on: an independent implementation reproduces the
// commitment. If this fails, no registry can issue in our format.
import { test } from 'node:test';
import assert from 'node:assert';
import { computeCommitment, verifyCommitment, canonicalise, COMMITMENT_ALGORITHM } from '../dist/index.js';

const record = {
  formatVersion: '0.1',
  recordId: 'vc_rec_test01',
  subjectType: 'plant-genetic-material',
  profile: 'veilcore/profile/cannabis/v0.1',
  commitment: '',
  commitmentAlgorithm: COMMITMENT_ALGORITHM,
  anchor: { chain: 'midnight', network: 'undeployed' },
  sealedAt: '2026-08-11T09:00:00Z',
  holder: { id: 'vc_hld_0001' },
  parents: [],
  attestations: [],
  profileData: { cultivarName: 'Test Cut', nonce: 'a'.repeat(64) },
};

test('canonicalisation sorts keys', () => {
  assert.equal(canonicalise({ b: 1, a: 2 }), '{"a":2,"b":1}');
});

test('an omitted field and an absent field hash identically', () => {
  assert.equal(canonicalise({ a: 1, b: undefined }), canonicalise({ a: 1 }));
});

test('array order is preserved, never sorted', () => {
  assert.equal(canonicalise(['b', 'a']), '["b","a"]');
});

test('the same record always produces the same commitment', async () => {
  const a = await computeCommitment(record);
  const b = await computeCommitment({ ...record });
  assert.equal(a, b);
});

test('key order in the source object does not change the commitment', async () => {
  const reordered = { profileData: record.profileData, recordId: record.recordId, ...record };
  assert.equal(await computeCommitment(record), await computeCommitment(reordered));
});

test('changing any committed field changes the commitment', async () => {
  const before = await computeCommitment(record);
  const after = await computeCommitment({
    ...record,
    profileData: { ...record.profileData, cultivarName: 'Different' },
  });
  assert.notEqual(before, after);
});

test('changing the anchor does not change the commitment', async () => {
  const before = await computeCommitment(record);
  const after = await computeCommitment({
    ...record,
    anchor: { chain: 'midnight', network: 'preview', txHash: '0xabc' },
  });
  assert.equal(before, after, 'the anchor is about the commitment and cannot be inside it');
});

test('verification accepts a correct commitment', async () => {
  const commitment = await computeCommitment(record);
  const res = await verifyCommitment({ ...record, commitment });
  assert.equal(res.valid, true);
});

test('verification rejects a tampered record', async () => {
  const commitment = await computeCommitment(record);
  const res = await verifyCommitment({
    ...record,
    commitment,
    profileData: { ...record.profileData, cultivarName: 'Tampered' },
  });
  assert.equal(res.valid, false);
});

test('an unknown commitment algorithm is refused rather than guessed', async () => {
  const res = await verifyCommitment({ ...record, commitmentAlgorithm: 'md5/whatever' });
  assert.equal(res.valid, false);
});
