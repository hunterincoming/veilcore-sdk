// Generate conformance vectors from the reference implementation.
//
// A specification nobody can test against is a specification everyone implements
// differently. These vectors are the difference between "compatible with VeilCore" as a
// claim and as a fact.
//
// EVERY vector lives in this file. Until August 2026 some sections were generated here
// and others were hand-edited into vectors.json, which meant running this script silently
// deleted the hand-written ones - including the entire rejections section, added after an
// external review found that the suite could not catch disagreement about invalid input.
// A file that is half generated and half maintained by hand has no single source, and the
// one that loses is always the hand-written half.
//
// SPDX-License-Identifier: Apache-2.0

import { writeFileSync, readFileSync } from 'node:fs';
import { canonicalise, computeCommitment, buildBatch, COMMITMENT_ALGORITHM } from '../dist/index.js';

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
  // Added after the August 2026 clean-room review. Each of these is a case where two
  // implementations had in fact diverged while passing every vector that then existed.
  { name: 'key above U+FFFF sorts by code point, not UTF-16 code unit', input: { '\u{1F600}': 2, '\uFF61': 1 } },
  { name: 'negative exponent uses ECMAScript form, not zero-padded', input: { n: 1e-7 } },
  { name: 'decomposed key is normalised to NFC before sorting', input: { 'e\u0301': 1 } },
  { name: 'integers within the safe range', input: { a: 0, b: -1, c: 9007199254740991 } },
];

const commitmentCases = [
  { name: 'minimal record', record: base },
  { name: 'anchor changes must not change the commitment', record: { ...base, anchor: { chain: 'midnight', network: 'preview', txHash: '0xdeadbeef' } } },
  { name: 'with one declared parent', record: { ...base, parents: [{ parentRecordId: 'vc_rec_parent', declaredBy: 'holder', verified: false }] } },
  { name: 'with an attestation', record: { ...base, attestations: [{ attestationId: 'att_1', type: 'genetic-fingerprint', attester: { id: 'lab_1' }, documentHash: 'f'.repeat(64), hashAlgorithm: 'sha256', issuedAt: '2026-01-02T00:00:00Z' }] } },
  { name: 'with a unicode cultivar name', record: { ...base, profileData: { ...base.profileData, cultivarName: 'Ölandsvete \u00e9' } } },
  // The three envelope fields every subject has. Added when they were found to be in the
  // code and not in the committed-field list, so a spec-conformant verifier reported a
  // genuine record as altered.
  {
    name: 'record carrying subject, identification and registrations',
    record: {
      formatVersion: '0.1',
      recordId: 'vc_rec_subject',
      subjectType: 'plant-genetic-material',
      profile: 'veilcore/profile/plant-variety/v1',
      commitment: '',
      commitmentAlgorithm: COMMITMENT_ALGORITHM,
      anchor: { chain: 'midnight', network: 'undeployed' },
      sealedAt: '2026-01-01T00:00:00Z',
      holder: { id: 'h1' },
      parents: [],
      attestations: [],
      subject: { name: 'Example variety', originator: 'A breeder', taxon: 'Glycine max' },
      identification: { method: 'molecular-marker', panel: 'BARCSoySSR13' },
      registrations: [{ authority: 'USDA PVPO', reference: '2026-0001', status: 'pending' }],
      profileData: { nonce: '0'.repeat(64), propagationType: 'seed' },
    },
  },
];

// Rejections. These are emitted verbatim rather than computed - an implementation is
// required to refuse them, so putting them through canonicalise() here would throw.
//
// A suite that only tests agreement on VALID input can never catch disagreement about
// what is invalid, which is how three implementations passed everything while disagreeing
// about nulls, key collisions and non-finite numbers.
const rejectionCases = [
  {
    name: 'explicit null at the top level is invalid',
    input: { a: null },
    reason: 'spec 4.4 rule 4',
  },
  {
    name: 'explicit null nested is invalid',
    input: { a: { b: null } },
    reason: 'spec 4.4 rule 4 applies at every depth',
  },
  {
    name: 'keys identical after normalisation are a collision',
    // Composed and decomposed forms of the same character. Distinct keys going in;
    // emitting both would produce an object with a duplicate key, which is not valid JSON.
    input: { '\u00e9': 1, 'e\u0301': 2 },
    reason: 'spec 4.4 rule 1; resolving it means two implementations resolve differently',
  },
  {
    name: 'non-finite numbers are invalid',
    construct: 'non-finite',
    reason: 'spec 4.4 rule 8. Not expressible in JSON, so the runner constructs it.',
  },
];

// Inclusion proofs. The fold is where a second implementation most plausibly diverges:
// domain separation between leaves and interior nodes, the direction bit, and the rule
// that an odd node is promoted rather than duplicated. The odd leaf counts are here
// deliberately - duplicating instead of promoting lets two different leaf sets produce
// the same root.
const batchCases = [
  { name: 'single-leaf batch', commitments: ['0'.repeat(64)] },
  { name: 'two leaves', commitments: ['0'.repeat(64), '1'.repeat(64)] },
  { name: 'odd leaf count promotes rather than duplicates', commitments: Array.from({ length: 5 }, (_, i) => `${i}`.repeat(64)) },
  { name: 'seven leaves, deeper path', commitments: Array.from({ length: 7 }, (_, i) => `${i}`.repeat(64)) },
];

const out = {
  formatVersion: '0.1',
  generatedAt: new Date().toISOString(),
  canonicalisation: [],
  commitments: [],
  inclusion: [],
  rejections: [],
};

for (const c of canonicalCases) {
  out.canonicalisation.push({ name: c.name, input: c.input, expected: canonicalise(c.input) });
}

for (const c of commitmentCases) {
  out.commitments.push({ name: c.name, record: c.record, expectedCommitment: await computeCommitment(c.record) });
}

for (const c of batchCases) {
  const batch = await buildBatch(c.commitments, 'B-CONFORMANCE', '2026-01-01T00:00:00Z');
  for (const commitment of c.commitments) {
    const proof = batch.proofs[commitment];
    out.inclusion.push({
      name: `${c.name} — ${commitment.slice(0, 4)}`,
      commitment,
      path: proof.path,
      expectedRoot: batch.root,
    });
  }
}

for (const c of rejectionCases) {
  const v = { name: c.name, reason: c.reason };
  if (c.construct) v.construct = c.construct;
  else v.input = c.input;
  out.rejections.push(v);
}

// Refuse to shrink the suite. A generated file that quietly drops vectors reports success
// while testing less, which is indistinguishable from passing.
const target = new URL('./vectors.json', import.meta.url);
try {
  const existing = JSON.parse(readFileSync(target, 'utf8'));
  const shrunk = Object.keys(out)
    .filter((k) => Array.isArray(out[k]))
    .filter((k) => Array.isArray(existing[k]) && out[k].length < existing[k].length)
    .map((k) => `${k}: ${existing[k].length} → ${out[k].length}`);
  const dropped = Object.keys(existing)
    .filter((k) => Array.isArray(existing[k]) && !Array.isArray(out[k]))
    .map((k) => `${k}: section removed entirely`);
  const losses = [...shrunk, ...dropped];
  if (losses.length && !process.argv.includes('--force')) {
    console.error('Refusing to write: this would remove vectors.\n');
    for (const l of losses) console.error(`  ${l}`);
    console.error('\nEvery vector should be defined in this file. If a case really is being');
    console.error('retired, say so in the commit and re-run with --force.');
    process.exit(1);
  }
} catch (e) {
  if (e?.code !== 'ENOENT') throw e; // no existing file is fine; anything else is not
}

writeFileSync(target, JSON.stringify(out, null, 2));
console.log(
  `generated ${out.canonicalisation.length} canonicalisation, ${out.commitments.length} commitment, ` +
  `${out.inclusion.length} inclusion and ${out.rejections.length} rejection vectors`
);
