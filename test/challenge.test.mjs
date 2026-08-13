// Third-party challenge.
//
// The tests that matter are the ones that stop this being a griefing tool: a challenge
// must be signed, must have a sealed claim behind it, and must never alter the record
// it contests.
import { test } from 'node:test';
import assert from 'node:assert';
import { generateKeypair, signChallenge, verifyChallenge, contestedStatus, computeCommitment } from '../dist/index.js';

const draft = (pub, over = {}) => ({
  challengeId: 'chal_1',
  subjectCommitment: 'a'.repeat(64),
  claimCommitment: 'b'.repeat(64),
  ground: 'prior-possession',
  statement: 'We held this cultivar from 2019 and can produce a record sealed then.',
  challenger: { publicKey: pub, displayName: 'Another breeder' },
  filedAt: '2026-08-13T10:00:00Z',
  state: 'open',
  ...over,
});

test('a signed challenge verifies', async () => {
  const kp = await generateKeypair();
  assert.equal(await verifyChallenge(await signChallenge(draft(kp.publicKey), kp.privateKey)), true);
});

test('an unsigned challenge does not', async () => {
  const kp = await generateKeypair();
  assert.equal(await verifyChallenge(draft(kp.publicKey)), false);
});

test('a challenge with no sealed claim behind it is refused', async () => {
  // Filing must cost something. Without a sealed record of the challenger own claim,
  // an assertion is free to make and there is nothing to weigh it against.
  const kp = await generateKeypair();
  const signed = await signChallenge(draft(kp.publicKey), kp.privateKey);
  assert.equal(await verifyChallenge({ ...signed, claimCommitment: '' }), false);
});

test('changing the statement breaks the signature', async () => {
  const kp = await generateKeypair();
  const signed = await signChallenge(draft(kp.publicKey), kp.privateKey);
  assert.equal(await verifyChallenge({ ...signed, statement: 'Something else entirely' }), false);
});

test('one party cannot file under another key', async () => {
  const real = await generateKeypair();
  const impostor = await generateKeypair();
  const signed = await signChallenge(draft(real.publicKey), real.privateKey);
  const swapped = { ...signed, challenger: { ...signed.challenger, publicKey: impostor.publicKey } };
  assert.equal(await verifyChallenge(swapped), false);
});

test('the record itself is untouched by a challenge', async () => {
  // The whole design rests on this: a record a stranger can alter is not evidence.
  const record = {
    formatVersion: '0.1', recordId: 'r1', subjectType: 'plant-genetic-material',
    profile: 'p/v1', commitment: '', commitmentAlgorithm: 'sha256/canonical-json/v1',
    anchor: { chain: 'midnight', network: 'undeployed' },
    sealedAt: '2026-01-01T00:00:00Z', holder: { id: 'h' },
    parents: [], attestations: [], profileData: { nonce: '0'.repeat(64) },
  };
  const before = await computeCommitment(record);
  const kp = await generateKeypair();
  await signChallenge(draft(kp.publicKey, { subjectCommitment: before }), kp.privateKey);
  assert.equal(await computeCommitment(record), before);
});

test('status is reported, never adjudicated', async () => {
  const kp = await generateKeypair();
  const c = draft(kp.publicKey);
  const none = contestedStatus([]);
  assert.equal(none.contested, false);

  const open = contestedStatus([c]);
  assert.equal(open.open, 1);
  assert.match(open.summary, /not a finding/, 'a challenge must not read as a verdict');

  const withdrawn = contestedStatus([{ ...c, state: 'withdrawn' }]);
  assert.equal(withdrawn.contested, false, 'a withdrawn challenge stops being reported');

  const resolved = contestedStatus([{ ...c, state: 'resolved' }]);
  assert.match(resolved.summary, /outside this system/, 'resolution comes from an authority, not from us');
});
