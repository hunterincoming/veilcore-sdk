// An Additional Certification Requirement, end to end.
//
// A variety owner can require that seed be tested for a specific trait before a
// certifying agency will certify it. The protocol is the owner's, not the
// agency's, and the numbers behind it are frequently a trade secret. That leaves
// the agency deciding eligibility on a result produced under a protocol it does
// not own, over data it cannot have and would rather not hold.
//
// The agency needs to know the specified test ran and returned the specified
// outcome. It does not want the data, and the owner will not hand it over.
//
// This example shows the record, the laboratory's attestation, and exactly what
// an agency receives. It runs with nothing but this package - no account, no
// network, no ledger:
//
//     npm install veilcore-records
//     node acr-trait-verification.mjs
//
// SPDX-License-Identifier: Apache-2.0

import {
  computeCommitment, verifyCommitment,
  generateKeypair, signAttestation, verifyAttestation,
  newNonce,
} from 'veilcore-records';

const line = (s) => console.log(`\n== ${s} ==`);
const say = (k, v) => console.log(`   ${k.padEnd(24)} ${v}`);

// The requirement, as the variety owner specifies it. Both halves are public:
// the agency has to know what it is checking, and a threshold nobody can read
// is not a standard.
const REQUIREMENT = {
  trait: 'profileData.trial.yieldKgPerHa',
  predicate: 'greaterOrEqual',
  threshold: 6000,
  unit: 'kg/ha',
  protocol: 'VCU/multisite-2y/v1',
};

line('1. The owner specifies the requirement');
say('trait', REQUIREMENT.trait);
say('standard', `>= ${REQUIREMENT.threshold} ${REQUIREMENT.unit}`);
say('protocol', REQUIREMENT.protocol);
console.log('\n   Published, because an agency cannot apply a standard it cannot read.');

// ---------------------------------------------------------------------------

line('2. The laboratory runs the test and the owner seals the result');

// The figure the owner will not publish. It sits inside profileData, which is
// covered by the commitment, so it cannot be changed after sealing without
// producing a different record.
const MEASURED = 6840;

const record = {
  formatVersion: '0.1',
  recordId: 'vc:northfield.example.com/NF-2026-0417',
  subjectType: 'plant-genetic-material',
  profile: 'veilcore/profile/plant-variety/v1',
  commitment: '',
  commitmentAlgorithm: 'sha256/canonical-json/v1',
  anchor: { chain: 'midnight', network: 'undeployed' },
  sealedAt: '2026-08-21T12:00:00Z',
  holder: { id: 'vc:northfield.example.com/holder' },
  parents: [],
  attestations: [],
  subject: {
    name: 'Northfield 0417',
    internalDesignation: 'NF-0417',
    originator: 'Northfield Breeding Programme',
  },
  profileData: {
    nonce: newNonce(),
    propagationType: 'seed',
    trial: {
      protocol: REQUIREMENT.protocol,
      seasons: 2,
      sites: 6,
      performedBy: 'Example Trials GmbH',
      // A yield without its protocol is not a statement, so the protocol
      // travels next to the figure rather than somewhere else.
      yieldKgPerHa: MEASURED,
    },
  },
};

record.commitment = await computeCommitment(record);
say('record', record.recordId);
say('commitment', record.commitment.slice(0, 32) + '...');
say('measured figure', 'held by the owner, never published');
say('verifies', (await verifyCommitment(record)).valid ? 'yes' : 'no');

// ---------------------------------------------------------------------------

line('3. The laboratory signs for the result');

// The agency is not being asked to trust the owner about the owner's own trial.
// Accuracy comes from a party with something to lose, and the signature is what
// binds the statement to that party rather than the name in a field.
const lab = await generateKeypair();

const attestation = await signAttestation({
  attestationId: 'att_vcu_0417',
  type: 'trial-result',
  attester: {
    id: 'lab:example-trials.example.com',
    name: 'Example Trials GmbH',
    // The key travels with the attestation. A verifier needs no side channel to
    // check the signature — establishing that the key belongs to a real
    // laboratory is a separate question, and what a trust registry is for.
    publicKey: lab.publicKey,
  },
  // Binds this attestation to THIS record. Without it a genuine signature could
  // be copied onto a different record and would verify there.
  subjectCommitment: record.commitment,
  documentHash: 'f'.repeat(64),
  hashAlgorithm: 'sha256',
  issuedAt: '2026-08-20T09:00:00Z',
}, lab.privateKey);

record.attestations = [attestation];
record.commitment = await computeCommitment(record);

const check = await verifyAttestation(attestation);
say('attester', attestation.attester.id);
say('signature', check ? 'verifies' : 'FAILED');
say('bound to', attestation.subjectCommitment.slice(0, 32) + '...');
console.log('\n   The report itself never enters the record. Only its hash. The lab keeps');
console.log('   the report and produces it if a dispute ever requires it.');

// ---------------------------------------------------------------------------

line('4. What the agency receives');

// Everything a certifying agency needs to make and later defend a determination,
// and nothing else. Note what is absent.
const filing = {
  record: record.recordId,
  commitment: record.commitment,
  requirement: {
    trait: REQUIREMENT.trait,
    predicate: REQUIREMENT.predicate,
    threshold: REQUIREMENT.threshold,
    unit: REQUIREMENT.unit,
    protocol: REQUIREMENT.protocol,
  },
  attester: attestation.attester,
  attestationStrength: 'signed',
  sealedAt: record.sealedAt,
};

console.log(JSON.stringify(filing, null, 2).split('\n').map((l) => '   ' + l).join('\n'));

console.log('\n   Absent: the measured figure, the trial data behind it, and every other');
console.log('   field of the record. The agency holds no copy of anything the owner');
console.log('   treats as a trade secret, so it carries none of the liability for it.');

// ---------------------------------------------------------------------------

line('5. What this example does not do, and where that is handled');

console.log(`
   The filing above states the requirement and identifies who stands behind the
   result. It does not by itself establish that the sealed figure MEETS the
   threshold - an agency reading it still has to be shown the figure, or take
   the attester's word.

   Establishing the threshold without disclosing the figure needs a per-field
   commitment scheme: each field committed as a leaf under a sealed root, so a
   claim can be proven about one field while the rest stay closed. Section 12 of
   the specification describes that as not yet specified here, and states the
   five things specifying it would have to settle.

   An independent implementation of that shape exists and has been exercised
   against records in this format. Two properties of it are worth knowing before
   an agency relies on one.

   A claim the sealed data does not support CANNOT BE CONSTRUCTED. It fails on
   the owner's own machine, nothing is published, and no fee is spent. An owner
   cannot publish a pass they did not earn, which is the half an agency relies on
   more than the passing case.

   And verification does not require the party that issued the claim. The result
   sits in state a verifier reads directly, so an agency confirms a determination
   years later without asking anyone - which is the same constraint as section 11:
   a record survives its registry.
`);

line('Summary');
console.log(`
   Specified by the owner:   the trait, the protocol, the standard
   Held by the owner:        the measured figure and the trial data
   Signed by the laboratory: that the result is theirs, bound to this record
   Held by the agency:       a determination it can defend, and no trade secret
`);
