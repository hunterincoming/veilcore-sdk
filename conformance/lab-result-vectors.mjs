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
for (const f of ['pathogen', 'genetic-match', 'lineage-check', 'dna-mark', 'lab-retraction']) {
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
  ['numbers under a published form', { ...common, kind: 'numbers', result: { form: 'veilcore/schema/seed-quality/v1' } }],
  [
    'text is NFC before it is hashed: a decomposed É hashes as the composed one',
    { ...common, kind: 'pathogen', sampleId: 'Échantillon-1', result: { target: 'HLVd', sampleType: 'feuille', detected: false } },
  ],
];
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
const [p0, p1, m, l2, l1, mk, rt, , nb] = cases.map(([, s]) => s);
const bound = [
  ['pathogen, not detected', p0, 'veilcore/schema/pathogen/v1', v16('0')],
  ['pathogen, detected, Ct 31.5 is 3150', p1, 'veilcore/schema/pathogen/v1', v16('1', '3150')],
  ['a comparison', m, 'veilcore/schema/genetic-match/v1', v16('1', '90', '0')],
  ['a parentage check, two parents', l2, 'veilcore/schema/lineage-check/v1', v16('1', '88', '0', '1')],
  ['a parentage check, one parent, nothing optional', l1, 'veilcore/schema/lineage-check/v1', v16('0')],
  ['a DNA mark', mk, 'veilcore/schema/dna-mark/v1', v16('1')],
  ['a withdrawal', rt, 'veilcore/schema/lab-retraction/v1', v16('1')],
  ['numbers under their own form', nb, 'veilcore/schema/seed-quality/v1', v16('9650', '9800')],
].map(([name, statement, form, values]) => ({ name, fields: recordFor(statement, form), statement, values, bound: true }));
const pf = recordFor(p0, 'veilcore/schema/pathogen/v1');
const unbound = [
  ['the statement changed after sealing', pf, { ...p0, sampleId: 'S-9999' }, v16('0')],
  ['the statement file’s size is wrong', { ...pf, files: [pf.files[0], { ...pf.files[1], size: pf.files[1].size + 1 }] }, p0, v16('0')],
  ['two statement files', { ...pf, files: [...pf.files, { ...pf.files[1], sha256: '00'.repeat(32) }] }, p0, v16('0')],
  ['no statement file', { ...pf, files: [pf.files[0]] }, p0, v16('0')],
  ['not a lab report', { ...pf, type: 'certificate-of-analysis' }, p0, v16('0')],
  ['dated another day than tested', { ...pf, issued: '2026-11-06' }, p0, v16('0')],
  ['under another kind’s form', recordFor(p0, 'veilcore/schema/genetic-match/v1'), p0, v16('0')],
  ['the call in the field set disagrees', pf, p0, v16('1')],
  ['a number the statement doesn’t have', pf, p0, v16('0', '3100')],
  ['no field set', (({ fieldSchema, fieldSetRoot, ...r }) => r)(pf), p0, v16('0')],
  ['numbers under a call form', recordFor({ ...nb, result: { form: 'veilcore/schema/pathogen/v1' } }, 'veilcore/schema/pathogen/v1'), { ...nb, result: { form: 'veilcore/schema/pathogen/v1' } }, v16('1')],
  ['a statement in a record not of the document profile', { ...pf, profile: 'veilcore/profile/plant-variety/v1' }, p0, v16('0')],
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

const out = {
  spec: 'SPEC 11.12, laboratory results version 2',
  schemas,
  labStatements: statements,
  labStatementRefusals: statementRefusals,
  labBindings: [...bound, ...unbound],
  markSeals,
  markRefusals,
};
writeFileSync(new URL('./lab-result-v2.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(
  `lab-result-v2.json: ${statements.length} statements, ${statementRefusals.length} statement refusals, ` +
    `${bound.length + unbound.length} bindings, ${markSeals.length} seals, ${markRefusals.length} seal refusals`,
);
