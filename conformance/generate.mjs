// Generate conformance vectors from the reference implementation.
//
// A specification nobody can test against is a specification everyone implements
// differently. These vectors are the difference between "compatible with VeilCore" as a
// claim and as a fact.
// SPDX-License-Identifier: Apache-2.0

import { writeFileSync } from 'node:fs';
import { canonicalise, computeCommitment, COMMITMENT_ALGORITHM } from '../dist/index.js';

const base = {
  formatVersion: '0.1',
  recordId: 'vc_rec_conformance_01',
  subjectType: 'plant-genetic-material',
  profile: 'veilcore/profile/cannabis/v0.1',
  commitment: '',
  commitmentAlgorithm: COMMITMENT_ALGORITHM,
  anchor: { chain: 'midnight', network: 'undeployed' },
  sealedAt: '2026-01-01T00:00:00Z',
  holder: { id: 'vc_hld_conformance' },
  parents: [],
  attestations: [],
  profileData: { cultivarName: 'Reference Cultivar', nonce: '0'.repeat(64) },
};

const canonicalCases = [
  { name: 'keys sorted by code point', input: { b: 1, a: 2, C: 3 } },
  { name: 'absent optional omitted, not null', input: { a: 1, b: undefined } },
  { name: 'array order preserved', input: ['b', 'a', 'c'] },
  { name: 'nested objects sorted at every level', input: { z: { b: 1, a: 2 }, a: 3 } },
  { name: 'NFC normalisation applied', input: { k: 'e\u0301' } },
  { name: 'empty object', input: {} },
  { name: 'empty array', input: [] },
  { name: 'booleans and numbers', input: { t: true, f: false, n: 0, neg: -1.5 } },
];

const commitmentCases = [
  { name: 'minimal record', record: base },
  { name: 'anchor changes must not change the commitment', record: { ...base, anchor: { chain: 'midnight', network: 'preview', txHash: '0xdeadbeef' } } },
  { name: 'with one declared parent', record: { ...base, parents: [{ parentRecordId: 'vc_rec_parent', declaredBy: 'holder', verified: false }] } },
  { name: 'with an attestation', record: { ...base, attestations: [{ attestationId: 'att_1', type: 'genetic-fingerprint', attester: { id: 'lab_1' }, documentHash: 'f'.repeat(64), hashAlgorithm: 'sha256', issuedAt: '2026-01-02T00:00:00Z' }] } },
  { name: 'with a unicode cultivar name', record: { ...base, profileData: { ...base.profileData, cultivarName: 'Ölandsvete \u00e9' } } },
];

const out = { formatVersion: '0.1', generatedAt: new Date().toISOString(), canonicalisation: [], commitments: [] };

for (const c of canonicalCases) {
  out.canonicalisation.push({ name: c.name, input: c.input, expected: canonicalise(c.input) });
}
for (const c of commitmentCases) {
  out.commitments.push({ name: c.name, record: c.record, expectedCommitment: await computeCommitment(c.record) });
}

writeFileSync(new URL('./vectors.json', import.meta.url), JSON.stringify(out, null, 2));
console.log(`generated ${out.canonicalisation.length} canonicalisation and ${out.commitments.length} commitment vectors`);
