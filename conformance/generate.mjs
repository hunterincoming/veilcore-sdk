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
import { canonicalise, computeCommitment, buildBatch, attestationPayload, COMMITMENT_ALGORITHM, fieldSetSummary, FIELDS_ALGORITHM } from '../dist/index.js';

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
  // Added October 2026 after a three-way differential run (27,000 inputs) found the
  // TypeScript, Python and Rust implementations disagreeing on numbers and on unpaired
  // surrogates. Given as JSON text, because what matters is how each implementation reads
  // the text: JSON has no way to write 95.0 that survives a JavaScript round trip.
  { name: 'a float with an integral value serialises as an integer (95.0)', inputText: '{"germinationPercent":95.0}' },
  { name: 'exponent input below 1e21 serialises in full (1e15)', inputText: '{"n":1e15}' },
  { name: 'small numbers use ECMAScript exponent form (1.5e-7)', inputText: '{"n":1.5E-7}' },
  { name: 'shortest digits that round-trip (0.1, 92.5, 12.75)', inputText: '{"a":0.1,"b":92.5,"c":12.75}' },
  { name: 'negative zero serialises as 0', inputText: '{"n":-0.0}' },
  { name: 'the largest safe integer, written as a float', inputText: '{"n":9007199254740991.0}' },
  { name: 'a surrogate pair written as escapes is one character', inputText: '{"k":"\\ud83d\\ude00"}' },
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
    // As text: a value built in JavaScript and sent through JSON.stringify arrives as
    // null, so the CLI runner was testing null rejection under this name.
    inputText: '{"n":1e999}',
    reason: 'spec 4.4 rule 8. 1e999 overflows a double to infinity.',
  },
  {
    name: 'an integer above 2^53 - 1 is invalid',
    inputText: '{"n":9007199254740992}',
    reason: 'spec 4.4 rule 8. JavaScript rounds 9007199254740993 to this value and Python keeps it exact.',
  },
  {
    name: 'a large integer written in full is invalid',
    inputText: '{"n":123456789012345678}',
    reason: 'spec 4.4 rule 8',
  },
  {
    name: 'a float above 2^53 - 1 is invalid (1e16)',
    inputText: '{"n":1e16}',
    reason: 'spec 4.4 rule 8',
  },
  {
    name: 'a negative number below -(2^53 - 1) is invalid',
    inputText: '{"n":-1.5e300}',
    reason: 'spec 4.4 rule 8',
  },
  {
    name: 'an unpaired high surrogate is invalid',
    inputText: '{"k":"X\\ud800"}',
    reason: 'spec 4.4 rule 1. It has no UTF-8 form; an encoder substitutes U+FFFD, so different strings would commit alike.',
  },
  {
    name: 'an unpaired low surrogate is invalid',
    inputText: '{"k":"\\udfff"}',
    reason: 'spec 4.4 rule 1',
  },
  {
    name: 'an unpaired surrogate in a key is invalid',
    inputText: '{"\\ud800":1}',
    reason: 'spec 4.4 rule 1',
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

// Attestation payloads. The bytes an attester signs, which until September 2026 no
// vector covered — so three implementations could disagree about what a signature
// protects and the suite would report all three conformant. It found exactly that:
// the TypeScript payload signed the attester's key and left displayName, role and
// accreditation outside the signature, which let anyone holding a genuine
// attestation rewrite them and still verify.
const attestationCases = [
  {
    name: 'minimal attestation',
    attestation: {
      attestationId: 'att_0001',
      type: 'laboratory-report',
      subjectCommitment: 'a'.repeat(64),
      attester: { publicKey: 'b'.repeat(64) },
      documentHash: 'c'.repeat(64),
      hashAlgorithm: 'sha256',
      issuedAt: '2026-01-01T00:00:00Z',
    },
  },
  {
    name: 'attester display name is inside the signed material',
    attestation: {
      attestationId: 'att_0002',
      type: 'laboratory-report',
      subjectCommitment: 'a'.repeat(64),
      attester: { publicKey: 'b'.repeat(64), displayName: 'Example Laboratory' },
      documentHash: 'c'.repeat(64),
      hashAlgorithm: 'sha256',
      issuedAt: '2026-01-01T00:00:00Z',
    },
  },
  {
    name: 'attester role is inside the signed material',
    attestation: {
      attestationId: 'att_0003',
      type: 'laboratory-report',
      subjectCommitment: 'a'.repeat(64),
      attester: { publicKey: 'b'.repeat(64), role: 'laboratory' },
      documentHash: 'c'.repeat(64),
      hashAlgorithm: 'sha256',
      issuedAt: '2026-01-01T00:00:00Z',
    },
  },
  {
    name: 'accreditation is inside the signed material',
    attestation: {
      attestationId: 'att_0004',
      type: 'laboratory-report',
      subjectCommitment: 'a'.repeat(64),
      attester: {
        publicKey: 'b'.repeat(64),
        displayName: 'Example Laboratory',
        role: 'laboratory',
        accreditation: { scheme: 'ISO/IEC 17025', identifier: 'L-1234', accreditor: 'A2LA' },
      },
      documentHash: 'c'.repeat(64),
      hashAlgorithm: 'sha256',
      issuedAt: '2026-01-01T00:00:00Z',
    },
  },
];

// Field sets (SPEC 4.5), added October 2026 with the claims contract. Every value here is
// plain SHA-256; the claims contract recomputes the same values in-circuit and its tests
// check them against this file (contract/src/test/claims-vectors.test.ts).
const exampleSchema = JSON.parse(readFileSync(new URL('../profiles/fields/plant-variety-dus-example-v1.json', import.meta.url), 'utf8'));
const loci = ['233/233', '180/184', '201/201', '155/159', '312/318', '140/140', '222/226', '199/199', '260/264', '175/175', '290/290', '133/137'];
const SECRET_A = '11'.repeat(32);
const fieldSetCases = [
  {
    name: 'twelve loci and four traits, slots 3 and 12 opened',
    input: { schema: exampleSchema, values: [...loci.map((t) => ({ text: t })), { uint: '9650' }, { uint: '9980' }, { uint: '6400' }, null], fieldSecret: SECRET_A, open: [3, 12, 15] },
  },
  {
    name: 'the number 0 is not an absent slot',
    input: { schema: exampleSchema, values: [...loci.map((t) => ({ text: t })), { uint: '0' }, null, { uint: '18446744073709551615' }, null], fieldSecret: '22'.repeat(32), open: [12, 13] },
  },
  {
    name: 'text is NFC-normalised before hashing (decomposed e-acute)',
    input: { schema: exampleSchema, values: [{ text: 'Caf\u0065\u0301' }, ...Array(15).fill(null)], fieldSecret: '33'.repeat(32), open: [0] },
  },
  {
    name: 'every slot absent',
    input: { schema: exampleSchema, values: Array(16).fill(null), fieldSecret: '44'.repeat(32), open: [] },
  },
];
const fieldRejectionCases = [
  { name: 'fifteen values', input: { schema: exampleSchema, values: Array(15).fill(null), fieldSecret: SECRET_A }, reason: 'a field set has exactly 16 slots' },
  { name: 'a uint above 2^64 - 1', input: { schema: exampleSchema, values: [{ uint: '18446744073709551616' }, ...Array(15).fill(null)], fieldSecret: SECRET_A }, reason: 'uint slots hold 0 to 2^64 - 1' },
  { name: 'a uint with a leading zero', input: { schema: exampleSchema, values: [{ uint: '07' }, ...Array(15).fill(null)], fieldSecret: SECRET_A }, reason: 'uint is a canonical decimal string' },
  { name: 'a negative uint', input: { schema: exampleSchema, values: [{ uint: '-1' }, ...Array(15).fill(null)], fieldSecret: SECRET_A }, reason: 'uint is a canonical decimal string' },
  { name: 'a value with both uint and text', input: { schema: exampleSchema, values: [{ uint: '1', text: 'x' }, ...Array(15).fill(null)], fieldSecret: SECRET_A }, reason: 'a slot value has exactly one kind' },
  { name: 'a schema with k = 0', input: { schema: { ...exampleSchema, k: 0 }, values: Array(16).fill(null), fieldSecret: SECRET_A }, reason: 'k is at least 1' },
  { name: 'a schema with k above its comparable slots', input: { schema: { ...exampleSchema, k: 13 }, values: Array(16).fill(null), fieldSecret: SECRET_A }, reason: 'k cannot exceed the comparable slots' },
  { name: 'a schema listing a slot twice', input: { schema: { ...exampleSchema, slots: [...exampleSchema.slots, exampleSchema.slots[0]] }, values: Array(16).fill(null), fieldSecret: SECRET_A }, reason: 'each slot is described once' },
  { name: 'text with an unpaired surrogate', input: { schema: exampleSchema, values: [{ text: 'a\ud800b' }, ...Array(15).fill(null)], fieldSecret: SECRET_A }, reason: 'the same rule as SPEC 4.4 rule 1' },
  { name: 'text in a uint slot', input: { schema: exampleSchema, values: [...Array(12).fill(null), { text: '96.5' }, null, null, null], fieldSecret: SECRET_A }, reason: 'a value matches its slot type' },
  { name: 'a uint in a text slot', input: { schema: exampleSchema, values: [{ uint: '233' }, ...Array(15).fill(null)], fieldSecret: SECRET_A }, reason: 'a value matches its slot type' },
  { name: 'a value in a slot the schema does not describe', input: { schema: { ...exampleSchema, slots: exampleSchema.slots.slice(0, 15) }, values: [...Array(15).fill(null), { uint: '1' }], fieldSecret: SECRET_A }, reason: 'undescribed slots are empty' },
  { name: 'an uppercase field secret', input: { schema: exampleSchema, values: Array(16).fill(null), fieldSecret: 'AB'.repeat(32) }, reason: 'hex is lowercase' },
];

const out = {
  formatVersion: '0.1',
  generatedAt: new Date().toISOString(),
  canonicalisation: [],
  commitments: [],
  inclusion: [],
  rejections: [],
  attestations: [],
  fieldSets: [],
  fieldRejections: [],
  commitmentRejections: [],
};

for (const c of canonicalCases) {
  if (c.inputText !== undefined) {
    out.canonicalisation.push({ name: c.name, inputText: c.inputText, expected: canonicalise(JSON.parse(c.inputText)) });
  } else {
    out.canonicalisation.push({ name: c.name, input: c.input, expected: canonicalise(c.input) });
  }
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
  if (c.inputText !== undefined) v.inputText = c.inputText;
  else v.input = c.input;
  out.rejections.push(v);
}

for (const c of fieldSetCases) {
  out.fieldSets.push({ name: c.name, input: c.input, expected: await fieldSetSummary(c.input) });
}
for (const c of fieldRejectionCases) {
  let threw = false;
  try { await fieldSetSummary(c.input); } catch { threw = true; }
  if (!threw) throw new Error(`the reference implementation accepted a field rejection vector: ${c.name}`);
  out.fieldRejections.push({ name: c.name, input: c.input, reason: c.reason });
}
// A record sealed with sha256/fields/v1: its commitment binds the first field set above.
{
  const fs = out.fieldSets[0].expected;
  const record = { ...base, recordId: 'vc_rec_conformance_fields_01', commitmentAlgorithm: FIELDS_ALGORITHM, fieldSchema: fs.schemaId, fieldSetRoot: fs.setRoot };
  out.commitments.push({ name: 'a sha256/fields/v1 record binds its field set', record, expectedCommitment: await computeCommitment(record) });
  for (const [name, r] of [
    ['a sha256/fields/v1 record without fieldSetRoot', { ...record, fieldSetRoot: undefined }],
    ['a sha256/fields/v1 record with an uppercase fieldSetRoot', { ...record, fieldSetRoot: record.fieldSetRoot.toUpperCase() }],
    ['a sha256/fields/v1 record without fieldSchema', { ...record, fieldSchema: undefined }],
    ['a sha256/fields/v1 record with fieldSchema as a list', { ...record, fieldSchema: [record.fieldSchema] }],
  ]) {
    let threw = false;
    try { await computeCommitment(r); } catch { threw = true; }
    if (!threw) throw new Error(`accepted: ${name}`);
    const clean = JSON.parse(JSON.stringify(r));
    out.commitmentRejections.push({ name, record: clean, reason: 'sha256/fields/v1 needs fieldSchema and fieldSetRoot as lowercase hex' });
  }
}

// Built before the shrink check below, which otherwise saw an empty attestations section
// and refused every run.
for (const c of attestationCases) {
  out.attestations.push({ name: c.name, attestation: c.attestation, expectedPayload: attestationPayload(c.attestation) });
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
  `${out.inclusion.length} inclusion, ${out.rejections.length} rejection, ${out.attestations.length} attestation, ` +
  `${out.fieldSets.length} field-set, ${out.fieldRejections.length} field-rejection and ${out.commitmentRejections.length} commitment-rejection vectors`
);

