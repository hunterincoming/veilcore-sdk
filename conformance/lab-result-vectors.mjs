// Vectors for laboratory results, version 2 (SPEC 11.12): lab-result-v2.json, next to this file.
//
// Computed here from the specification with node:crypto and this package's canonicaliser only,
// never with either implementation's lab-result code (the reference's src/lab-result.ts, or the
// VeilCore web application's): the TypeScript, Python and web implementations are all tested
// against values none of them computed. The schema documents are copied byte for byte from the
// web application's public/schemas/ and this package's profiles/fields/.
//
//   node conformance/lab-result-vectors.mjs     (after npm run build), then npm run conformance:generate
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { canonicalise } from '../dist/index.js';

const sha = (b) => createHash('sha256').update(b).digest();
const hex = (b) => Buffer.from(b).toString('hex');
const enc = (s) => Buffer.from(s, 'utf8');

// ---- schema ids (SPEC 4.5), computed here ----
const tag32 = (t) => {
  const b = Buffer.alloc(32);
  enc(t).copy(b);
  return b;
};
const schemaId = (schema) => {
  const terms = Buffer.alloc(32);
  let comparable = 0;
  let numeric = 0;
  for (const s of schema.slots) {
    if (s.comparable) comparable |= 1 << s.slot;
    if (s.type === 'uint') numeric |= 1 << s.slot;
  }
  terms.writeUInt16LE(comparable, 0);
  terms.writeUInt16LE(numeric, 2);
  terms[4] = schema.k;
  return hex(sha(Buffer.concat([tag32('veilcore:v1:fschema'), sha(enc(canonicalise(schema))), terms])));
};
const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const schemas = {};
for (const f of ['pathogen', 'genetic-match', 'lineage-check', 'dna-mark', 'viability', 'lab-retraction']) {
  const s = read(`../profiles/fields/${f}-v1.json`);
  schemas[s.id] = s;
}
// One numbers form, as the web application publishes it.
const seed = read('../profiles/fields/seed-quality-v1.json');
schemas[seed.id] = seed;

// ---- statements ----
const A = 'a1'.repeat(32);
const B = 'b2'.repeat(32);
const C = 'c3'.repeat(32);
const common = {
  format: 'veilcore/lab-result/v2',
  subject: A,
  sampleId: 'S-0412',
  accession: 'LAB-26-1187',
  method: { id: 'RT-qPCR HLVd SOP-14', version: '3' },
  tested: '2026-11-05',
};
const cases = [
  ['pathogen, not detected, the least a result carries', { ...common, kind: 'pathogen', result: { target: 'HLVd', sampleType: 'leaf', detected: false } }],
  [
    'pathogen, detected, with Ct, QC, received and a panel',
    {
      ...common,
      kind: 'pathogen',
      received: '2026-11-03',
      panel: { id: 'Viroid panel', version: '2026.1' },
      qc: [
        { name: 'Internal control Ct', value: '24.1' },
        { name: 'Extraction blank', value: 'passed' },
      ],
      result: { target: 'HLVd', sampleType: 'root', detected: true, ct: '31.5' },
    },
  ],
  [
    'a comparison with another record, by proof code',
    { ...common, kind: 'match', method: { id: 'SNP genotyping', version: '4' }, panel: { id: 'CannSNP90', version: '2.1' }, result: { other: B, matches: true, compared: 90, differing: 0 } },
  ],
  [
    'a parentage check against two parents',
    { ...common, kind: 'lineage', method: { id: 'SNP parentage', version: '1' }, result: { parents: [B, C], consistent: true, compared: 88, conflicts: [0, 1] } },
  ],
  ['a parentage check against one parent, excluded', { ...common, kind: 'lineage', result: { parents: [B], consistent: false } }],
  [
    'a DNA mark, sealed, with the lab’s name for it',
    { ...common, kind: 'dna-mark', method: { id: 'Mark PCR', version: '1' }, result: { seal: 'd4'.repeat(32), found: true, label: 'Line mark 7' } },
  ],
  ['a withdrawal of an earlier result', { ...common, kind: 'retraction', replaces: { result: B, reason: 'retraction' } }],
  ['a re-test that replaces an earlier result', { ...common, kind: 'pathogen', result: { target: 'HLVd', sampleType: 'leaf', detected: false }, replaces: { result: C, reason: 're-test' } }],
  [
    'a comparison naming the other sample too',
    { ...common, kind: 'match', method: { id: 'SNP genotyping', version: '4' }, result: { other: B, otherSampleId: 'REF-0007', matches: false, compared: 90, differing: 31 } },
  ],
  [
    'a pathogen test with twelve run and QC details, the most',
    {
      ...common,
      kind: 'pathogen',
      qc: Array.from({ length: 12 }, (_, i) => ({ name: `detail ${i + 1}`, value: String(i) })),
      result: { target: 'HLVd', sampleType: 'TC plantlet', detected: false },
    },
  ],
  ['numbers under a published form', { ...common, kind: 'numbers', result: { form: 'veilcore/schema/seed-quality/v1' } }],
  [
    'text is NFC before it is hashed: a decomposed É hashes as the composed one',
    { ...common, kind: 'pathogen', sampleId: 'Échantillon-1', result: { target: 'HLVd', sampleType: 'feuille', detected: false } },
  ],
  [
    'a result with the salt of its name binding, as every result is now signed',
    { ...common, kind: 'pathogen', result: { target: 'HLVd', sampleType: 'leaf', detected: false }, bindingSalt: '9e'.repeat(16) + '4c'.repeat(16) },
  ],
];

// ---- viability: a sample taken before or after a kill step (SPEC 11.12, "Viability") ----
const D = 'd4'.repeat(32); // the strain record the batch was made from
const viable = {
  ...common,
  kind: 'viability',
  sampleId: 'MEAL-0907-PRE',
  accession: 'LAB-26-2201',
  // The before- and after-sample are tested by one method, so the pair says the method recovered
  // the strain from this material before the kill step (SPEC 11.12, "The pair").
  method: { id: 'Membrane filtration onto PDA, SOP-M7', version: '2' },
  received: '2026-11-03',
  tested: '2026-11-10',
  qc: [{ name: 'Medium lot', value: 'PDA-2611' }],
  result: {
    batch: 'MEAL-26-0907',
    stage: 'before',
    strain: D,
    sampled: '2026-11-02',
    target: 'The production strain',
    portion: '10 g of meal in 90 mL, then 1 mL of a 1 in 10 000 dilution filtered',
    cultures: [{ medium: 'PDA with chloramphenicol', time: '7 days', temperature: '25 °C' }],
    lod: { value: '100000', unit: 'CFU/g' },
    detected: true,
    count: { value: '4300000', unit: 'CFU/g' },
    controls: { positive: 'Production strain, about 50 CFU', positiveGrew: true, negativeGrew: false },
  },
  bindingSalt: '6b'.repeat(16) + '2a'.repeat(16),
};
const beforeCode = 'e5'.repeat(32); // the before result's code, as the after result names it
const viableAfter = {
  ...viable,
  sampleId: 'MEAL-0907-POST',
  accession: 'LAB-26-2202',
  result: {
    ...viable.result,
    stage: 'after',
    killStep: 'Steam, 95 °C core for 30 min, then dried at 70 °C',
    before: beforeCode,
    sampled: '2026-11-03',
    portion: '25 g of meal in 225 mL, all of it filtered, half onto each medium',
    cultures: [
      { medium: 'PDA with chloramphenicol', time: '7 days', temperature: '25 °C' },
      { medium: 'DG18 agar', time: '7 days', temperature: '25 °C' },
    ],
    lod: { value: '1', unit: 'CFU per 25 g' },
    detected: false,
    // None recovered: no count. The limit of detection says it (< 1 CFU per 25 g).
    count: undefined,
  },
};
const viableLeast = (({ count, ...r }) => ({
  ...viableAfter,
  qc: undefined,
  received: undefined,
  result: { ...r, before: undefined, controls: { positive: 'A. brasiliensis ATCC 16404', positiveGrew: true } },
}))(viableAfter.result);
const clean = (o) => JSON.parse(JSON.stringify(o));
cases.push(
  ['viability: a before-sample, organisms recovered, with a count', viable],
  ['viability: an after-sample naming its before-sample, none recovered in two media (no count)', clean(viableAfter)],
  ['viability: an after-sample, the least it carries (no before-sample, no negative control)', clean(viableLeast)],
  ['viability: sent under the strain record itself', { ...viable, subject: D }],
);
const statements = cases.map(([name, statement]) => {
  const bytes = enc(canonicalise(statement));
  return { name, statement, canonical: bytes.toString('utf8'), sha256: hex(sha(bytes)), size: bytes.length };
});

const pathogen = cases[0][1];
const statementRefusals = [
  ['an older format', { ...pathogen, format: 'veilcore/lab-result/v1' }],
  ['a field the format doesn’t have', { ...pathogen, notes: 'x' }],
  ['no method', (({ method, ...r }) => r)(pathogen)],
  ['a kind the format doesn’t have', { ...pathogen, kind: 'potency' }],
  ['a subject in upper case', { ...pathogen, subject: A.toUpperCase() }],
  ['a sample ID with a space at the end', { ...pathogen, sampleId: 'S-0412 ' }],
  ['an empty accession number', { ...pathogen, accession: '' }],
  ['a zero-width space in the sample ID', { ...pathogen, sampleId: 'S-04\u200b12' }],
  ['a right-to-left override in the accession number', { ...pathogen, accession: 'LAB-\u202e1187' }],
  ['thirteen QC details', { ...pathogen, qc: Array.from({ length: 13 }, (_, i) => ({ name: `d${i}`, value: '1' })) }],
  ['a mark label that is a sequence', { ...pathogen, kind: 'dna-mark', result: { seal: 'd4'.repeat(32), found: true, label: 'mark acgtacgtac' } }],
  ['an empty other sample ID', { ...pathogen, kind: 'match', result: { other: B, otherSampleId: '', matches: true } }],
  ['a method without its version', { ...pathogen, method: { id: 'RT-qPCR' } }],
  ['a panel with an empty version', { ...pathogen, panel: { id: 'P', version: '' } }],
  ['a date tested that isn’t a date', { ...pathogen, tested: '2026-02-30' }],
  ['received after tested', { ...pathogen, received: '2026-11-06' }],
  ['an empty QC list (omitted, not empty)', { ...pathogen, qc: [] }],
  ['a QC name repeated', { ...pathogen, qc: [{ name: 'a', value: '1' }, { name: 'a', value: '2' }] }],
  ['Ct with three decimals', { ...pathogen, result: { ...pathogen.result, ct: '31.255' } }],
  ['Ct of 100', { ...pathogen, result: { ...pathogen.result, ct: '100' } }],
  ['detected written as text', { ...pathogen, result: { ...pathogen.result, detected: 'no' } }],
  ['a comparison with the sample’s own record', { ...pathogen, kind: 'match', result: { other: A, matches: true } }],
  ['more markers differing than compared', { ...pathogen, kind: 'match', result: { other: B, matches: false, compared: 5, differing: 6 } }],
  ['a parent named twice', { ...pathogen, kind: 'lineage', result: { parents: [B, B], consistent: true } }],
  ['conflicts for fewer parents than named', { ...pathogen, kind: 'lineage', result: { parents: [B, C], consistent: true, conflicts: [1] } }],
  ['a mark seal that isn’t a hash', { ...pathogen, kind: 'dna-mark', result: { seal: 'xyz', found: true } }],
  ['a withdrawal that carries a result', { ...pathogen, kind: 'retraction', replaces: { result: B, reason: 'retraction' } }],
  ['a withdrawal that names nothing', (({ result, ...r }) => ({ ...r, kind: 'retraction' }))(pathogen)],
  ['a re-test given the reason retraction', { ...pathogen, replaces: { result: B, reason: 'retraction' } }],
  ['a reason the format doesn’t have', { ...pathogen, replaces: { result: B, reason: 'because' } }],
  ['a binding salt in upper case', { ...pathogen, bindingSalt: '9E'.repeat(32) }],
  ['a binding salt of 31 bytes', { ...pathogen, bindingSalt: '9e'.repeat(31) }],
  ['a binding salt that is all one byte value', { ...pathogen, bindingSalt: '00'.repeat(32) }],
  ['a binding salt written as a number', { ...pathogen, bindingSalt: 7 }],
  ['viability: a stage the format doesn’t have', { ...viable, result: { ...viable.result, stage: 'during' } }],
  ['viability: an after-sample with no kill step', { ...viableAfter, result: (({ killStep, ...r }) => r)(viableAfter.result) }],
  ['viability: a before-sample with a kill step', { ...viable, result: { ...viable.result, killStep: 'Steam' } }],
  ['viability: a before-sample naming a before-sample', { ...viable, result: { ...viable.result, before: beforeCode } }],
  ['viability: no strain record', { ...viable, result: (({ strain, ...r }) => r)(viable.result) }],
  ['viability: a strain named by name, not by proof code', { ...viable, result: { ...viable.result, strain: 'Aspergillus oryzae RIB40' } }],
  ['viability: no batch', { ...viable, result: { ...viable.result, batch: '' } }],
  ['viability: sampled after the date tested', { ...viable, result: { ...viable.result, sampled: '2026-11-11' } }],
  ['viability: sampled after the date received', { ...viable, result: { ...viable.result, sampled: '2026-11-04' } }],
  ['viability: no medium', { ...viable, result: { ...viable.result, cultures: [] } }],
  ['viability: five media', { ...viable, result: { ...viable.result, cultures: Array.from({ length: 5 }, (_, i) => ({ medium: `M${i}`, time: '7 days', temperature: '25 °C' })) } }],
  ['viability: the same medium twice', { ...viable, result: { ...viable.result, cultures: [viable.result.cultures[0], viable.result.cultures[0]] } }],
  ['viability: a medium with no temperature', { ...viable, result: { ...viable.result, cultures: [{ medium: 'PDA', time: '7 days' }] } }],
  ['viability: a limit of detection of 0', { ...viable, result: { ...viable.result, lod: { value: '0', unit: 'CFU/g' } } }],
  ['viability: a limit of detection with an exponent', { ...viable, result: { ...viable.result, lod: { value: '1e2', unit: 'CFU/g' } } }],
  ['viability: a limit of detection with no unit', { ...viable, result: { ...viable.result, lod: { value: '100', unit: '' } } }],
  ['viability: a count written as a number', { ...viable, result: { ...viable.result, count: { value: 4300000, unit: 'CFU/g' } } }],
  ['viability: none recovered with a count above 0', { ...viableAfter, result: { ...viableAfter.result, count: { value: '3', unit: 'CFU per 25 g' } } }],
  ['viability: none recovered with a count of 0 (below the limit of detection is not 0)', { ...viableAfter, result: { ...viableAfter.result, count: { value: '0', unit: 'CFU per 25 g' } } }],
  ['viability: recovered with a count of 0', { ...viable, result: { ...viable.result, count: { value: '0', unit: 'CFU/g' } } }],
  ['viability: recovered with no count', { ...viable, result: (({ count, ...r }) => r)(viable.result) }],
  ['viability: a count with an exponent', { ...viable, result: { ...viable.result, count: { value: '4.3e6', unit: 'CFU/g' } } }],
  ['viability: a negative count', { ...viable, result: { ...viable.result, count: { value: '-4300000', unit: 'CFU/g' } } }],
  ['viability: a count with a plus sign', { ...viable, result: { ...viable.result, count: { value: '+4300000', unit: 'CFU/g' } } }],
  ['viability: a count with a thousands comma', { ...viable, result: { ...viable.result, count: { value: '4,300,000', unit: 'CFU/g' } } }],
  ['viability: a limit of detection with a decimal comma', { ...viable, result: { ...viable.result, lod: { value: '0,5', unit: 'CFU/g' } } }],
  ['viability: a limit of detection with a space between thousands', { ...viable, result: { ...viable.result, lod: { value: '100 000', unit: 'CFU/g' } } }],
  ['viability: detected written as text', { ...viable, result: { ...viable.result, detected: 'no growth' } }],
  ['viability: a positive control that did not grow (an invalid run)', { ...viable, result: { ...viable.result, controls: { ...viable.result.controls, positiveGrew: false } } }],
  ['viability: a negative control that grew (an invalid run)', { ...viable, result: { ...viable.result, controls: { ...viable.result.controls, negativeGrew: true } } }],
  ['viability: no positive control', { ...viable, result: { ...viable.result, controls: { positiveGrew: true } } }],
  ['viability: a field the result doesn’t have', { ...viable, result: { ...viable.result, sterile: true } }],
].map(([name, statement]) => ({ name, statement }));

// ---- bindings: the statement inside a document record's committed fields ----
const fileOf = (s) => {
  const b = enc(canonicalise(s));
  return { name: 'lab-result.json', sha256: hex(sha(b)), size: b.length };
};
const recordFor = (s, form, extra = {}) => ({
  about: [{ name: s.sampleId }],
  fieldSchema: schemaId(schemas[form]),
  fieldSetRoot: 'e5'.repeat(32),
  files: [{ name: 'report.pdf', sha256: 'f6'.repeat(32), size: 51234 }, fileOf(s)],
  holder: 'Example Plant Lab',
  issued: s.tested,
  issuer: 'Example Plant Lab',
  loggedAt: 1793000000000,
  nonce: '07'.repeat(32),
  notes: '',
  profile: 'veilcore/profile/document/v1',
  reference: s.accession,
  title: s.accession,
  type: 'lab-report',
  ...extra,
});
const v16 = (...xs) => Array.from({ length: 16 }, (_, i) => (xs[i] === undefined ? null : xs[i]));
const [p0, p1, m, l2, l1, mk, rt, , mo, q12, nb, , , vb, va, vl] = cases.map(([, s]) => s);
const bound = [
  ['pathogen, not detected', p0, 'veilcore/schema/pathogen/v1', v16('0')],
  ['pathogen, detected, Ct 31.5 is 3150', p1, 'veilcore/schema/pathogen/v1', v16('1', '3150')],
  ['a comparison', m, 'veilcore/schema/genetic-match/v1', v16('1', '90', '0')],
  ['a parentage check, two parents', l2, 'veilcore/schema/lineage-check/v1', v16('1', '88', '0', '1')],
  ['a parentage check, one parent, nothing optional', l1, 'veilcore/schema/lineage-check/v1', v16('0')],
  ['a DNA mark', mk, 'veilcore/schema/dna-mark/v1', v16('1')],
  ['a withdrawal', rt, 'veilcore/schema/lab-retraction/v1', v16('1')],
  ['a comparison naming the other sample, no match', mo, 'veilcore/schema/genetic-match/v1', v16('0', '90', '31')],
  ['a pathogen test with twelve run and QC details', q12, 'veilcore/schema/pathogen/v1', v16('0')],
  ['numbers under their own form', nb, 'veilcore/schema/seed-quality/v1', v16('9650', '9800')],
  ['viability: a before-sample, recovered', vb, 'veilcore/schema/viability/v1', v16('1', '0')],
  ['viability: an after-sample, none recovered', va, 'veilcore/schema/viability/v1', v16('0', '1')],
  ['viability: an after-sample, the least it carries', vl, 'veilcore/schema/viability/v1', v16('0', '1')],
].map(([name, statement, form, values]) => ({ name, fields: recordFor(statement, form), statement, values, bound: true }));
const pf = recordFor(p0, 'veilcore/schema/pathogen/v1');
const unbound = [
  ['the statement changed after sealing', pf, { ...p0, sampleId: 'S-9999' }, v16('0')],
  ['the statement file’s size is wrong', { ...pf, files: [pf.files[0], { ...pf.files[1], size: pf.files[1].size + 1 }] }, p0, v16('0')],
  ['two statement files', { ...pf, files: [...pf.files, { ...pf.files[1], sha256: '00'.repeat(32) }] }, p0, v16('0')],
  ['no statement file', { ...pf, files: [pf.files[0]] }, p0, v16('0')],
  ['not a lab report', { ...pf, type: 'certificate-of-analysis' }, p0, v16('0')],
  ['dated another day than tested', { ...pf, issued: '2026-11-06' }, p0, v16('0')],
  ['the record names another sample in about', { ...pf, about: [{ name: 'S-9999' }] }, p0, v16('0')],
  ['the record names a second record in about', { ...pf, about: [{ name: 'S-0412' }, { name: 'other' }] }, p0, v16('0')],
  ['the record’s reference isn’t the accession number', { ...pf, reference: 'LAB-26-0000' }, p0, v16('0')],
  ['the record’s issuer isn’t its holder (two lab names)', { ...pf, issuer: 'Another Lab' }, p0, v16('0')],
  ['under another kind’s form', recordFor(p0, 'veilcore/schema/genetic-match/v1'), p0, v16('0')],
  ['the call in the field set disagrees', pf, p0, v16('1')],
  ['a number the statement doesn’t have', pf, p0, v16('0', '3100')],
  ['no field set', (({ fieldSchema, fieldSetRoot, ...r }) => r)(pf), p0, v16('0')],
  ['numbers under a call form', recordFor({ ...nb, result: { form: 'veilcore/schema/pathogen/v1' } }, 'veilcore/schema/pathogen/v1'), { ...nb, result: { form: 'veilcore/schema/pathogen/v1' } }, v16('1')],
  ['a statement in a record not of the document profile', { ...pf, profile: 'veilcore/profile/plant-variety/v1' }, p0, v16('0')],
  ['viability: the field set says before, the statement after', recordFor(va, 'veilcore/schema/viability/v1'), va, v16('0', '0')],
  ['viability: the field set says none recovered, the statement some', recordFor(vb, 'veilcore/schema/viability/v1'), vb, v16('0', '0')],
  ['viability: the field set leaves out the stage', recordFor(va, 'veilcore/schema/viability/v1'), va, v16('0')],
  ['viability: under the pathogen form', recordFor(va, 'veilcore/schema/pathogen/v1'), va, v16('0', '1')],
].map(([name, fields, statement, values]) => ({ name, fields, statement, values, bound: false }));

// ---- DNA mark seals ----
const MARK = Buffer.concat([enc('veilcore:dnamark:v1'), Buffer.from([0])]);
const seal = (sequence, salt) => hex(sha(Buffer.concat([MARK, Buffer.from(salt, 'hex'), enc(sequence)])));
const markSeals = [
  ['the shortest mark, a zero salt', 'ACGTACGTAC', '00'.repeat(32)],
  ['a 40-letter mark', 'ACGTTGCAACGTTGCAGGCCTTAAGGCCTTAAACGTACGT', '5a'.repeat(32)],
  ['the same mark, another salt, another seal', 'ACGTTGCAACGTTGCAGGCCTTAAGGCCTTAAACGTACGT', 'a5'.repeat(32)],
].map(([name, sequence, salt]) => ({ name, sequence, salt, seal: seal(sequence, salt) }));
const markRefusals = [
  ['nine letters', 'ACGTACGTA', '00'.repeat(32)],
  ['lower case', 'acgtacgtac', '00'.repeat(32)],
  ['an ambiguity code', 'ACGTNACGTA', '00'.repeat(32)],
  ['white space inside', 'ACGTA CGTAC', '00'.repeat(32)],
  ['a short salt', 'ACGTACGTAC', '00'.repeat(31)],
].map(([name, sequence, salt]) => ({ name, sequence, salt }));

// ---- the laboratory's name binding (salted) ----
// SHA-256("veilcore:lab-result-binding:v2:salted" 0x00 || key (64 bytes) || subject || salt).
// The key is hashed as bytes; that it is a point on the curve is the signature's concern.
const NAME = Buffer.concat([enc('veilcore:lab-result-binding:v2:salted'), Buffer.from([0])]);
const nameBinding = (key, subject, salt) =>
  hex(sha(Buffer.concat([NAME, Buffer.from(key, 'hex'), Buffer.from(subject, 'hex'), Buffer.from(salt, 'hex')])));
const K1 = '1f'.repeat(32) + '2e'.repeat(32);
const K2 = '3d'.repeat(32) + '4c'.repeat(32);
const S1 = '9e'.repeat(16) + '4c'.repeat(16);
const S2 = '4c'.repeat(16) + '9e'.repeat(16);
const nameBindings = [
  ['a key, a subject and a salt', K1, A, S1],
  ['the same key and subject, another salt, another binding', K1, A, S2],
  ['the same key and salt, another subject', K1, B, S1],
  ['another key', K2, A, S1],
].map(([name, key, subject, salt]) => ({ name, key, subject, salt, nameBinding: nameBinding(key, subject, salt) }));
const nameBindingRefusals = [
  ['a salt that is all one byte value', K1, A, '00'.repeat(32)],
  ['a key of 127 hex characters', K1.slice(1), A, S1],
  ['a subject in upper case', K1, A.toUpperCase(), S1],
].map(([name, key, subject, salt]) => ({ name, key, subject, salt }));

// ---- viability pairs: an after-sample and the before-sample it names ----
// `beforeCode` stands for the before result's code (its record commitment); the after names it.
// `afterCode` stands for the after result's own code. `held` is every other result the verifier
// holds signed by the same key, each with its code: one that replaces or withdraws either breaks the pair.
const afterCode = 'ab'.repeat(32);
const pairOf = (name, after, before, paired, held = []) => ({ name, after, before, beforeCode, afterCode, held, paired });
const withdrawal = (code, over = {}) => ({
  ...common,
  kind: 'retraction',
  sampleId: 'MEAL-0907-W',
  accession: 'LAB-26-2209',
  tested: '2026-11-12',
  replaces: { result: code, reason: 'retraction' },
  bindingSalt: '7c'.repeat(16) + '3d'.repeat(16),
  ...over,
});
const W = 'f7'.repeat(32); // a withdrawal's or re-test's own code
const viableBefore = { ...viable }; // the before-sample above
const viablePairs = [
  pairOf('an after-sample and the before-sample it names', viableAfter, viableBefore, true),
  pairOf('the before-sample also showed none recovered: still a pair, read as it is', viableAfter, { ...viableBefore, result: { ...viableBefore.result, detected: false, count: undefined } }, true),
  pairOf('the after-sample names another result', { ...viableAfter, result: { ...viableAfter.result, before: 'f6'.repeat(32) } }, viableBefore, false),
  pairOf('the after-sample names no before-sample', clean(viableLeast), viableBefore, false),
  pairOf('another batch', viableAfter, { ...viableBefore, result: { ...viableBefore.result, batch: 'MEAL-26-0908' } }, false),
  pairOf('another strain record', viableAfter, { ...viableBefore, result: { ...viableBefore.result, strain: C } }, false),
  pairOf('the before-sample was taken the same day as the after-sample', viableAfter, { ...viableBefore, result: { ...viableBefore.result, sampled: '2026-11-03' } }, true),
  pairOf('the "before" is itself an after-sample', viableAfter, { ...viableAfter, result: { ...viableAfter.result, before: undefined } }, false),
  pairOf('the "before" is a pathogen result', viableAfter, p0, false),
  pairOf('the two tests recover different things (target)', viableAfter, { ...viableBefore, result: { ...viableBefore.result, target: 'Total aerobic count (bacteria only)' } }, false),
  pairOf('the two tests used different methods: still a pair, and a verifier says the methods differ', viableAfter, { ...viableBefore, method: { id: 'Spread plate on PDA, SOP-M4', version: '1' } }, true),
  pairOf('the before-sample’s result is withdrawn', viableAfter, viableBefore, false, [{ statement: withdrawal(beforeCode), code: W }]),
  pairOf('the after-sample’s result is withdrawn', viableAfter, viableBefore, false, [{ statement: withdrawal(afterCode), code: W }]),
  pairOf('the before-sample’s result is replaced by a re-test', viableAfter, viableBefore, false, [{ statement: { ...viableBefore, accession: 'LAB-26-2210', tested: '2026-11-11', replaces: { result: beforeCode, reason: 're-test' } }, code: W }]),
  pairOf('a withdrawal of another result: still a pair', viableAfter, viableBefore, true, [{ statement: withdrawal('f6'.repeat(32)), code: W }]),
  pairOf('a withdrawal for another record tested replaces nothing: still a pair', viableAfter, viableBefore, true, [{ statement: withdrawal(beforeCode, { subject: B }), code: W }]),
  pairOf('a withdrawal dated before the result replaces nothing: still a pair', viableAfter, viableBefore, true, [{ statement: withdrawal(beforeCode, { tested: '2026-11-09' }), code: W }]),
].map((p) => clean(p));
// Taken the same day is not after: the pair above stands. One taken a day later does not pair.
viablePairs.push(
  clean(pairOf('the before-sample was taken a day after the after-sample', viableAfter, { ...viableBefore, received: '2026-11-04', result: { ...viableBefore.result, sampled: '2026-11-04' } }, false)),
);

const out = {
  spec: 'SPEC 11.12, laboratory results version 2',
  schemas,
  labStatements: statements,
  labStatementRefusals: statementRefusals,
  labBindings: [...bound, ...unbound],
  markSeals,
  markRefusals,
  labNameBindings: nameBindings,
  labNameBindingRefusals: nameBindingRefusals,
  labViabilityPairs: viablePairs,
};
writeFileSync(new URL('./lab-result-v2.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(
  `lab-result-v2.json: ${statements.length} statements, ${statementRefusals.length} statement refusals, ` +
    `${bound.length + unbound.length} bindings, ${markSeals.length} seals, ${markRefusals.length} seal refusals, ` +
    `${nameBindings.length} name bindings, ${nameBindingRefusals.length} name binding refusals, ` +
    `${viablePairs.length} viability pairs`,
);
