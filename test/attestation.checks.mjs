/**
 * What a signature on an attestation actually covers.
 *
 * An attestation is worth what the attester is worth, so every field a verifier
 * reads to decide that has to be inside the signature. attestationPayload once
 * signed attester.publicKey alone, which left displayName, role and accreditation
 * outside it: a genuine attestation from a small lab could be rewritten to claim
 * an accredited one, signature untouched, still verifying. The strength tiers
 * read exactly those fields.
 *
 *   node attestation-checks.mjs
 */
import { generateKeypair, signAttestation, verifyAttestation } from '../dist/index.js';

let failures = 0;
const ok = (n, c, d) => { if (c) console.log(`OK   ${n}`); else { console.error(`FAIL ${n}${d ? `\n     ${d}` : ''}`); failures++; } };

const kp = await generateKeypair();
const base = {
  attestationId: 'att_1', type: 'laboratory-report',
  subjectCommitment: 'aa'.repeat(32),
  attester: { publicKey: kp.publicKey, displayName: 'Small Lab', role: 'laboratory' },
  documentHash: 'bb'.repeat(32), hashAlgorithm: 'sha256',
  issuedAt: '2026-01-01T00:00:00Z',
};
const real = await signAttestation(base, kp.privateKey);
const tamper = async (f) => { const c = JSON.parse(JSON.stringify(real)); f(c); return verifyAttestation(c); };

ok('a genuine attestation verifies', await verifyAttestation(real));

console.log('\n== fields a verifier reads to weigh the attestation ==');
ok('renaming the attester breaks it', !(await tamper((c) => { c.attester.displayName = 'Eurofins'; })));
ok('adding accreditation breaks it', !(await tamper((c) => {
  c.attester.accreditation = { scheme: 'ISO/IEC 17025', identifier: 'L-9999', accreditor: 'A2LA' };
})), 'this is the one that turns a signed attestation into an accredited one');
ok('changing the role breaks it', !(await tamper((c) => { c.attester.role = 'registry'; })));

console.log('\n== the claim itself ==');
ok('moving it to another record breaks it', !(await tamper((c) => { c.subjectCommitment = 'cc'.repeat(32); })),
   'without this an attestation can be lifted onto a record it was never about');
ok('changing the document hash breaks it', !(await tamper((c) => { c.documentHash = 'dd'.repeat(32); })));
ok('backdating it breaks it', !(await tamper((c) => { c.issuedAt = '2020-01-01T00:00:00Z'; })));
ok('changing the type breaks it', !(await tamper((c) => { c.type = 'genetic-fingerprint'; })));
ok('swapping the key breaks it', !(await tamper((c) => { c.attester.publicKey = 'ee'.repeat(32); })));

console.log('\n== the signature itself ==');
ok('an absent signature does not verify', !(await tamper((c) => { delete c.signature; })));
ok('a truncated signature does not verify', !(await tamper((c) => { c.signature = c.signature.slice(0, -2); })));
ok('an empty signature does not verify', !(await tamper((c) => { c.signature = ''; })));

console.log(`\n${failures === 0 ? 'no findings' : `${failures} finding(s)`}`);
process.exit(failures === 0 ? 0 : 1);
