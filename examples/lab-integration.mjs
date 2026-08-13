// Integrating VeilCore into a laboratory's own system.
//
// This is what adoption looks like in practice: a lab keeps its LIMS, its intake
// process, and its own database. It adds a commitment to each record it already
// creates, and signs the reports it already issues.
//
// Nothing here touches a VeilCore account, and no sample description is sent
// anywhere. Run it with:
//
//     npm install veilcore-records
//     node lab-integration.mjs
//
// SPDX-License-Identifier: Apache-2.0

import {
  computeCommitment, verifyCommitment,
  generateKeypair, signAttestation, verifyAttestation,
  buildBatch, verifyInclusion,
  newNonce,
} from 'veilcore-records';

const line = (s) => console.log(`\n== ${s} ==`);

line('1. A lab receives a sample and records what arrived');

// The lab's own intake data. It stays in the lab's own system; only the commitment
// computed from it is ever published.
const intake = {
  formatVersion: '0.1',
  recordId: 'LAB-2026-00417',
  subjectType: 'plant-genetic-material',
  profile: 'veilcore/profile/cannabis/v0.1',
  commitment: '',
  commitmentAlgorithm: 'sha256/canonical-json/v1',
  anchor: { chain: 'midnight', network: 'undeployed' },
  sealedAt: '2026-08-13T09:15:00Z',
  holder: { id: 'lab:northfield', displayName: 'Northfield Analytical' },
  parents: [],
  attestations: [],
  profileData: {
    cultivarName: 'Client submission 417',
    breedingMethod: 'Clone / cutting',
    custodyContext: 'Received from client, 12 plantlets, chain-of-custody form signed',
    // The nonce makes the commitment hiding as well as binding. Without it, a
    // guessable description could be confirmed by computing candidates.
    nonce: newNonce(),
  },
};

intake.commitment = await computeCommitment(intake);
console.log('commitment:', intake.commitment);
console.log('verifies:  ', (await verifyCommitment(intake)).valid);

line('2. The lab signs the report it produced');

// Generated once, kept by the lab. The private key never leaves their systems: a
// report signed by anyone else is a claim about the lab rather than by it.
const labKey = await generateKeypair();

// The report is not uploaded. Its hash proves later that a produced document is
// the one that was signed.
const reportHash = 'c'.repeat(64);

const attestation = await signAttestation({
  attestationId: 'LAB-2026-00417-COA',
  type: 'laboratory-report',
  subjectCommitment: intake.commitment,
  attester: { publicKey: labKey.publicKey, displayName: 'Northfield Analytical', role: 'laboratory' },
  documentHash: reportHash,
  hashAlgorithm: 'sha256',
  issuedAt: '2026-08-20T14:00:00Z',
}, labKey.privateKey);

console.log('signature verifies:', await verifyAttestation(attestation));
console.log('tampered verifies: ', await verifyAttestation({ ...attestation, documentHash: 'f'.repeat(64) }));

line('3. A day of records is anchored in one transaction');

const theDay = [
  intake.commitment,
  await computeCommitment({ ...intake, recordId: 'LAB-2026-00418', profileData: { ...intake.profileData, nonce: newNonce() } }),
  await computeCommitment({ ...intake, recordId: 'LAB-2026-00419', profileData: { ...intake.profileData, nonce: newNonce() } }),
];

const batch = await buildBatch(theDay, 'NORTHFIELD-2026-08-13');
console.log('records in batch:', theDay.length);
console.log('root to publish: ', batch.root);

const proof = batch.proofs[intake.commitment];
console.log('client proof path:', proof.path.length, 'sibling hashes');
console.log('proof verifies:   ', await verifyInclusion(proof));

line('4. What the client can prove, years later');

console.log('Record unaltered since sealing:  ', (await verifyCommitment(intake)).valid);
console.log('Included in the anchored batch:  ', await verifyInclusion(proof));
console.log('Report signed by the lab:        ', await verifyAttestation(attestation));
console.log('\nWhat remains is a ledger lookup for the batch root, which fixes the date.');
console.log('None of the above required an account, a server, or our permission.');
