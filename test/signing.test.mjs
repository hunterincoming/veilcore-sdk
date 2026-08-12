// Attester signatures.
//
// A signature is what makes an attestation belong to someone. The tests that matter are
// the negative ones: a forged attestation must fail, and a third party must not be able
// to retract someone else's work.
import { test } from 'node:test';
import assert from 'node:assert';
import {
  generateKeypair, signAttestation, verifyAttestation,
  signRetraction, verifyRetraction, strengthOf, attesterId,
} from '../dist/index.js';

const draft = (pub) => ({
  attestationId: 'att_1',
  type: 'genetic-fingerprint',
  subjectCommitment: 'a'.repeat(64),
  attester: { publicKey: pub, displayName: 'Test Lab', role: 'laboratory' },
  documentHash: 'b'.repeat(64),
  hashAlgorithm: 'sha256',
  issuedAt: '2026-01-01T00:00:00Z',
});

test('a signed attestation verifies', async () => {
  const kp = await generateKeypair();
  const signed = await signAttestation(draft(kp.publicKey), kp.privateKey);
  assert.equal(await verifyAttestation(signed), true);
});

test('an unsigned attestation does not verify', async () => {
  const kp = await generateKeypair();
  assert.equal(await verifyAttestation(draft(kp.publicKey)), false);
});

test('tampering with the subject breaks the signature', async () => {
  const kp = await generateKeypair();
  const signed = await signAttestation(draft(kp.publicKey), kp.privateKey);
  assert.equal(await verifyAttestation({ ...signed, subjectCommitment: 'f'.repeat(64) }), false);
});

test('tampering with the document hash breaks the signature', async () => {
  const kp = await generateKeypair();
  const signed = await signAttestation(draft(kp.publicKey), kp.privateKey);
  assert.equal(await verifyAttestation({ ...signed, documentHash: 'f'.repeat(64) }), false);
});

test('a signature from one key does not verify against another', async () => {
  const lab = await generateKeypair();
  const impostor = await generateKeypair();
  const signed = await signAttestation(draft(lab.publicKey), lab.privateKey);
  const swapped = { ...signed, attester: { ...signed.attester, publicKey: impostor.publicKey } };
  assert.equal(await verifyAttestation(swapped), false, 'an impostor must not be able to claim an attestation');
});

test('the issuing lab can retract its own attestation', async () => {
  const kp = await generateKeypair();
  const signed = await signAttestation(draft(kp.publicKey), kp.privateKey);
  const r = await signRetraction({
    attestationId: 'att_1', attesterPublicKey: kp.publicKey,
    reason: 'issued-in-error', retractedAt: '2026-02-01T00:00:00Z',
  }, kp.privateKey);
  assert.equal(await verifyRetraction(r, signed), true);
});

test('a third party cannot retract someone else attestation', async () => {
  const lab = await generateKeypair();
  const other = await generateKeypair();
  const signed = await signAttestation(draft(lab.publicKey), lab.privateKey);
  const forged = await signRetraction({
    attestationId: 'att_1', attesterPublicKey: other.publicKey,
    reason: 'issued-in-error', retractedAt: '2026-02-01T00:00:00Z',
  }, other.privateKey);
  assert.equal(await verifyRetraction(forged, signed), false, 'only the issuing key may retract');
});

test('a retraction for a different attestation is refused', async () => {
  const kp = await generateKeypair();
  const signed = await signAttestation(draft(kp.publicKey), kp.privateKey);
  const r = await signRetraction({
    attestationId: 'att_OTHER', attesterPublicKey: kp.publicKey,
    reason: 'issued-in-error', retractedAt: '2026-02-01T00:00:00Z',
  }, kp.privateKey);
  assert.equal(await verifyRetraction(r, signed), false);
});

test('strength reflects signature and accreditation, and nothing else', async () => {
  const kp = await generateKeypair();
  const signed = await signAttestation(draft(kp.publicKey), kp.privateKey);
  assert.equal(strengthOf(draft(kp.publicKey)), 'unsigned');
  assert.equal(strengthOf(signed), 'signed');
  assert.equal(strengthOf({
    ...signed,
    attester: { ...signed.attester, accreditation: { scheme: 'ISO/IEC 17025', identifier: 'X', accreditor: 'Y' } },
  }), 'signed-and-accredited');
});

test('an attester id is derived from the key, not the name', async () => {
  const kp = await generateKeypair();
  const a = await attesterId(kp.publicKey);
  const b = await attesterId(kp.publicKey);
  assert.equal(a, b);
  assert.match(a, /^vc_att_[0-9a-f]{16}$/);
});
