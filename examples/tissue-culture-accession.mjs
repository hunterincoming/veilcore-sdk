// Generation depth, and why anyone should believe it.
//
// A tissue culture laboratory takes custody of somebody else's material, cleans
// it, and sells plantlets propagated from it. Material rooted directly out of
// sterile culture is priced above material that has been grown out in a normal
// environment and returned - the argument being that the value of
// micropropagation is the sterility of the environment, and a plant that has
// left it is no different from any other clone.
//
// That difference is a number: how many subcultures deep the material is. The
// number is written down by the laboratory selling the material. A buyer who
// knows the lab takes it. A buyer who doesn't is taking their word.
//
// This example builds the chain. Each subculture is its own record naming the
// one above it, so generation depth is something a buyer walks rather than
// something they are told. It also shows what a depositor sees, which is their
// own material and nothing about anyone else in the building.
//
// Nothing here needs an account or a network:
//
//     npm install veilcore-records
//     node tissue-culture-accession.mjs
//
// SPDX-License-Identifier: Apache-2.0

import {
  computeCommitment, verifyCommitment,
  generateKeypair, signAttestation, verifyAttestation,
  newNonce,
} from 'veilcore-records';

const line = (s) => console.log(`\n== ${s} ==`);
const say = (k, v) => console.log(`   ${k.padEnd(24)} ${v}`);

// verifyCommitment and verifyAttestation report a result object rather than a
// bare boolean, so that a failure can say why. Reading the object as a boolean
// would make every check pass, which is the kind of mistake that only shows up
// when something is supposed to fail and doesn't.
const ok = (r) => (typeof r === 'boolean' ? r : r?.valid === true);

const LAB = 'lab:oxbow.example.com';
const PROFILE = 'veilcore/profile/tissue-culture-accession/v1';

// One record per step. The laboratory keeps all of them; only the commitments
// are ever published.
const accession = async ({ id, sealedAt, parents, profileData, subject }) => {
  const record = {
    formatVersion: '0.1',
    recordId: `vc:oxbow.example.com/${id}`,
    subjectType: 'plant-genetic-material',
    profile: PROFILE,
    commitment: '',
    commitmentAlgorithm: 'sha256/canonical-json/v1',
    anchor: { chain: 'midnight', network: 'undeployed' },
    sealedAt,
    holder: { id: LAB, displayName: 'Oxbow Micropropagation' },
    parents,
    profileData: { nonce: newNonce(), ...profileData },
  };
  // Anything added after the commitment is computed is not covered by it, and a
  // verifier will say so. Everything the record claims goes in before sealing.
  if (subject) record.subject = subject;
  record.commitment = await computeCommitment(record);
  return record;
};

line('1. Material arrives from a depositor');

// What came in, from whom, when. This is the record that answers a dispute two
// years later about who deposited what. The depositor is named in `subject`,
// which is an envelope field because a herd book and a culture collection both
// need one.
const intake = await accession({
  id: 'ACC-2026-0088',
  sealedAt: '2026-03-04T08:20:00Z',
  parents: [],
  subject: {
    name: 'Ridgeline Selection 14',
    originator: 'Ridgeline Farms',
    claimedCreationDate: '2019',
  },
  profileData: {
    stage: 'stage-0',
    generation: 0,
    initiatedOn: '2026-03-04',
    indexingStatus: 'not-indexed',
    notes: 'Six unrooted cuttings received, chain-of-custody form signed',
  },
});
say('record', intake.recordId);
say('generation', intake.profileData.generation);
say('commitment', intake.commitment.slice(0, 24) + '...');

line('2. The laboratory genotypes it and signs the result');

// The fingerprint itself never leaves the lab. What travels is an attestation
// bound to this record by its commitment - so the same signed report cannot be
// lifted onto a different accession, because the binding is inside the signature.
const lab = await generateKeypair();

const genotype = await signAttestation({
  attestationId: 'OXB-GT-2026-0311',
  type: 'genotype',
  attester: { id: LAB, displayName: 'Oxbow Micropropagation', publicKey: lab.publicKey },
  subjectCommitment: intake.commitment,
  documentHash: await computeCommitment({ panel: 'SSR-10', report: 'internal file, not published' }),
  hashAlgorithm: 'sha256',
  issuedAt: '2026-03-11T14:00:00Z',
}, lab.privateKey);

say('attestation', genotype.attestationId);
say('bound to', genotype.subjectCommitment.slice(0, 24) + '...');
say('verifies', ok(await verifyAttestation(genotype)) ? 'yes' : 'no');

line('3. Initiation into culture');

// A meristem rather than a nodal segment, which matters: meristem culture
// excludes systemic infection in a way a nodal segment does not, so it changes
// what a later screening result means. The intake record is the parent, in the
// role that says where the accession came from.
const initiated = await accession({
  id: 'ACC-2026-0088-G0',
  sealedAt: '2026-03-18T10:05:00Z',
  parents: [{ recordId: intake.recordId, role: 'accession-source', commitment: intake.commitment }],
  profileData: {
    stage: 'stage-I',
    generation: 0,
    explantType: 'meristem',
    mediumReference: 'OXB-M-114',
    indexingStatus: 'clean',
    initiatedOn: '2026-03-18',
  },
});

say('record', initiated.recordId);
say('stage', initiated.profileData.stage);
say('explant', initiated.profileData.explantType);
say('medium', initiated.profileData.mediumReference + '   (reference, not formulation)');
say('indexing', initiated.profileData.indexingStatus);

line('4. Two subcultures');

// Each transfer is a new record naming the one above it. This is the whole
// mechanism: the number in a record is not a claim on its own, it is the length
// of a chain anyone can walk.
const g1 = await accession({
  id: 'ACC-2026-0088-G1',
  sealedAt: '2026-04-22T09:40:00Z',
  parents: [{ recordId: initiated.recordId, role: 'subculture-parent', commitment: initiated.commitment }],
  profileData: {
    stage: 'stage-II',
    generation: 1,
    explantType: 'nodal-segment',
    mediumReference: 'OXB-M-207',
    indexingStatus: 'clean',
  },
});

const g2 = await accession({
  id: 'ACC-2026-0088-G2',
  sealedAt: '2026-05-27T09:15:00Z',
  parents: [{ recordId: g1.recordId, role: 'subculture-parent', commitment: g1.commitment }],
  profileData: {
    stage: 'stage-III',
    generation: 2,
    explantType: 'nodal-segment',
    mediumReference: 'OXB-M-301',
    indexingStatus: 'clean',
  },
});

for (const r of [g1, g2]) say(r.recordId.split('/')[1], `generation ${r.profileData.generation}, ${r.profileData.stage}`);

line('5. What a buyer can establish');

// The chain, walked. A buyer holding these records checks each commitment and
// each parent link. Nothing here requires the laboratory's cooperation and
// nothing requires ours.
const chain = [intake, initiated, g1, g2];

let intact = true;
for (const r of chain) if (!ok(await verifyCommitment(r))) intact = false;

for (let i = 1; i < chain.length; i++) {
  const declared = chain[i].parents[0];
  if (declared.commitment !== chain[i - 1].commitment) intact = false;
}

say('records unaltered', intact ? 'yes' : 'no');
say('chain length', `${chain.length - 1} transfers from intake`);
say('depth claimed', g2.profileData.generation);
say('depth shown', chain.length - 2);
say('genotype attestation', ok(await verifyAttestation(genotype)) ? 'signed by the named lab' : 'not verified');

line('6. The same claim, without the chain');

// A record can say anything. What it cannot do is name a parent whose
// commitment does not match. Here is generation zero asserted on material that
// is three records deep - the number changes, the chain does not support it.
const overstated = { ...g2, profileData: { ...g2.profileData, generation: 0 } };

const check = await verifyCommitment(overstated);

say('claims generation', overstated.profileData.generation);
say('commitment holds', ok(check) ? 'yes' : 'no');
if (!ok(check)) say('reason', check.reason);
say('parent chain shows', chain.length - 2);

line('7. What the depositor sees');

// Ridgeline deposited the material. They are shown their own accession and the
// attestation about it. They are not shown the other depositors in the same
// building, their cultivars, their media, or that they exist.
say('shown', 'ACC-2026-0088 and its chain');
say('shown', 'the genotype attestation, signed');
say('not shown', 'other depositors');
say('not shown', 'their cultivars or accessions');
say('not shown', 'media formulations (references only)');
say('not shown', 'the fingerprint values themselves');

console.log(`
The generation number is the thing being sold. Until now it has been a figure in
a laboratory's own system, believed by people who already trust the laboratory.
Built as a chain, it is a length anyone can measure - and the laboratory hands
over nothing to make that possible.
`);
