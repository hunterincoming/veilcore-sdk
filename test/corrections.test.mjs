// Correction severity.
//
// The rule these enforce: severity is classified by which field changed, never chosen.
// If a holder could pick, every correction would be cosmetic — nobody flags their own
// correction as the kind that invalidates their downstream agreements.
import { test } from 'node:test';
import assert from 'node:assert';
import { diffRecords, classifyCorrection, supersedesFor } from '../dist/index.js';

const base = {
  formatVersion: '0.1', recordId: 'vc_rec_1', subjectType: 'plant-genetic-material',
  profile: 'veilcore/profile/cannabis/v0.1', commitment: 'a'.repeat(64),
  commitmentAlgorithm: 'sha256/canonical-json/v1',
  anchor: { chain: 'midnight', network: 'undeployed' },
  sealedAt: '2026-01-01T00:00:00Z', holder: { id: 'h1' }, parents: [], attestations: [],
  profileData: { cultivarName: 'Original', breederName: 'B', notes: '', nonce: '0'.repeat(64) },
};
const edit = (path, value) => {
  const c = structuredClone(base);
  const [a, b] = path.split('.');
  if (b) c[a][b] = value; else c[a] = value;
  return c;
};

test('a typo in notes is cosmetic for both', () => {
  const s = classifyCorrection(diffRecords(base, edit('profileData.notes', 'fixed typo')));
  assert.equal(s.descent, 'cosmetic');
  assert.equal(s.terms, 'cosmetic');
});

test('a cultivar name change is cosmetic for descent, material for terms', () => {
  const s = classifyCorrection(diffRecords(base, edit('profileData.cultivarName', 'Renamed')));
  assert.equal(s.descent, 'cosmetic', 'the plant did not change');
  assert.equal(s.terms, 'material', 'the name may be the licensed thing');
});

test('changing parents is material for descent', () => {
  const s = classifyCorrection(diffRecords(base, edit('parents', [{ parentRecordId: 'x', declaredBy: 'holder', verified: false }])));
  assert.equal(s.descent, 'material');
});

test('a correction does not report its own seal time as a change', () => {
  // A correcting record is a new record and is always sealed later than the one it
  // supersedes. Reporting that as a change would make every correction material and the
  // classification meaningless. Backdating is prevented instead by the original record
  // never being altered or deleted: its own seal time and anchor remain checkable.
  const s = classifyCorrection(diffRecords(base, edit('sealedAt', '2020-01-01T00:00:00Z')));
  assert.equal(s.descent, 'cosmetic');
  assert.equal(s.terms, 'cosmetic');
});

test('one material change makes the whole correction material', () => {
  const both = structuredClone(base);
  both.profileData.notes = 'typo';
  both.parents = [{ parentRecordId: 'x', declaredBy: 'holder', verified: false }];
  const s = classifyCorrection(diffRecords(base, both));
  assert.equal(s.descent, 'material', 'a material change is not diluted by cosmetic ones');
});

test('an unclassified field defaults to material rather than harmless', () => {
  const c = structuredClone(base);
  c.profileData.somethingNew = 'value';
  const s = classifyCorrection(diffRecords(base, c));
  assert.equal(s.descent, 'material');
});

test('the commitment and anchor differing does not count as a change', () => {
  const c = structuredClone(base);
  c.commitment = 'f'.repeat(64);
  c.anchor = { chain: 'midnight', network: 'preview', txHash: '0xabc' };
  assert.equal(diffRecords(base, c).length, 0);
});

test('supersedes names the changed fields without their values', () => {
  const s = supersedesFor(base, edit('profileData.cultivarName', 'New'), 'misspelled', 'holder');
  assert.deepEqual(s.changedFields, ['profileData.cultivarName']);
  assert.equal(JSON.stringify(s).includes('New'), false, 'values must not leak into the supersedes block');
  assert.equal(s.recordId, 'vc_rec_1');
});
