// Multiple anchors.
//
// A commitment can be bound to a time several ways, and jurisdictions disagree about
// which they recognise. The property that makes carrying several possible is that none
// of them is inside the commitment.
import { test } from 'node:test';
import assert from 'node:assert';
import { computeCommitment, anchorsOf, effectiveAnchors, standingOf, datingSummary } from '../dist/index.js';

const base = {
  formatVersion: '0.1', recordId: 'r1', subjectType: 'plant-genetic-material',
  profile: 'p/v1', commitment: '', commitmentAlgorithm: 'sha256/canonical-json/v1',
  anchor: { chain: 'midnight', network: 'undeployed' },
  sealedAt: '2026-01-01T00:00:00Z', holder: { id: 'h' },
  parents: [], attestations: [], profileData: { nonce: '0'.repeat(64) },
};

const ledger = { kind: 'ledger', chain: 'midnight', network: 'preview', txHash: 'a'.repeat(64) };
const qualified = {
  kind: 'rfc3161', chain: 'n/a', network: 'n/a', token: 'MIIF...',
  tsa: 'DigiCert', qualified: { scheme: 'eIDAS', trustedList: 'EU' },
};
const plainTsa = { kind: 'rfc3161', chain: 'n/a', network: 'n/a', token: 'MIIF...', tsa: 'Some TSA' };

test('adding anchors does not change the commitment', async () => {
  // Without this, carrying several anchors would be impossible: each addition would
  // produce a different record.
  const one = await computeCommitment({ ...base, anchor: ledger });
  const many = await computeCommitment({ ...base, anchor: [ledger, qualified] });
  const none = await computeCommitment({ ...base, anchor: { chain: 'x', network: 'undeployed' } });
  assert.equal(one, many);
  assert.equal(one, none);
});

test('a single anchor and an array of one are the same thing', () => {
  assert.equal(anchorsOf({ ...base, anchor: ledger }).length, 1);
  assert.equal(anchorsOf({ ...base, anchor: [ledger] }).length, 1);
});

test('an undeployed anchor establishes nothing', () => {
  assert.equal(effectiveAnchors({ ...base, anchor: { chain: 'midnight', network: 'undeployed' } }).length, 0);
  assert.equal(effectiveAnchors({ ...base, anchor: ledger }).length, 1);
});

test('a qualified timestamp is reported as carrying a presumption', () => {
  const s = standingOf(qualified);
  assert.equal(s.presumption, true);
  assert.match(s.note, /Article 42/);
  assert.match(s.note, /Verify the provider/, 'the claim is the attester\'s, not ours');
});

test('an unqualified timestamp is reported as carrying none', () => {
  const s = standingOf(plainTsa);
  assert.equal(s.presumption, false);
  assert.match(s.note, /no presumption/);
});

test('a ledger anchor names where it is recognised, without overclaiming', () => {
  const s = standingOf(ledger);
  assert.equal(s.presumption, false, 'no general presumption attaches to a chain anchor');
  assert.match(s.note, /Italian Law 12\/2019/);
  assert.match(s.note, /proved rather than presumed/);
});

test('an unanchored record says so plainly', () => {
  assert.match(datingSummary(base), /rests on whoever holds it/);
});

test('several anchors are summarised without claiming more than one supports', () => {
  const both = datingSummary({ ...base, anchor: [ledger, qualified] });
  assert.match(both, /2 ways/);
  assert.match(both, /presumption/);
  const chainOnly = datingSummary({ ...base, anchor: [ledger] });
  assert.match(chainOnly, /depends on where you are/);
});
