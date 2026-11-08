// Laboratory results, version 2 (SPEC 11.12): a result statement bound into the document record a
// laboratory signs. Ported from the VeilCore web application's lab-result.ts; checked against
// conformance/lab-result-v2.json, whose values were computed by conformance/lab-result-vectors.mjs
// with node:crypto and this package's canonicaliser only.
//
// This module checks the statement's form, gives the file entry a record carries for it, checks
// the binding of a statement to a record's committed fields and field-set values, and seals a DNA
// mark. The laboratory's signature over the record commitment (SPEC 4.5) is checked as for any
// laboratory-signed record; it is not here.
// SPDX-License-Identifier: Apache-2.0

import { canonicalise } from './canonical.js';
import { toHex } from './hash.js';
import { fieldSchemaId, type FieldSchema } from './fields.js';
import { validateDocumentFields } from './document-profile.js';

export const LAB_RESULT_FORMAT = 'veilcore/lab-result/v2';
export const LAB_RESULT_FILE_NAME = 'lab-result.json';
export const LAB_RESULT_KINDS = ['numbers', 'pathogen', 'match', 'lineage', 'dna-mark', 'retraction'] as const;
export type LabResultKind = (typeof LAB_RESULT_KINDS)[number];
/** The most QC and run details a statement carries. */
export const LAB_QC_MAX = 12;
export const LAB_REPLACE_REASONS = ['re-test', 'correction', 'retraction'] as const;

/** The form each kind's field set is sealed under; a `numbers` result names its own. */
export const LAB_CALL_SCHEMAS: Readonly<Record<Exclude<LabResultKind, 'numbers'>, string>> = {
  pathogen: 'veilcore/schema/pathogen/v1',
  match: 'veilcore/schema/genetic-match/v1',
  lineage: 'veilcore/schema/lineage-check/v1',
  'dna-mark': 'veilcore/schema/dna-mark/v1',
  retraction: 'veilcore/schema/lab-retraction/v1',
};

const subtle = (): SubtleCrypto | undefined => (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
const sha256 = async (bytes: Uint8Array): Promise<Uint8Array> => {
  const s = subtle();
  if (s) return new Uint8Array(await s.digest('SHA-256', bytes as BufferSource));
  const nodeCrypto = await import(/* @vite-ignore */ 'node' + ':crypto');
  return new Uint8Array(nodeCrypto.createHash('sha256').update(bytes).digest());
};

const HEX64 = /^[0-9a-f]{64}$/;
const CONTROL = /\p{Cc}/u;
/** Format characters (bidi controls, zero-width spaces): refused in one-line text, so two values that look the same are the same. */
const FORMAT = /\p{Cf}/u;
/** A label that could be the mark itself: ten or more of A, C, G, T in a row. */
const SEQUENCE_RUN = /[ACGT]{10,}/i;
const CT = /^(0|[1-9]\d?)(\.\d{1,2})?$/;
const COUNT_MAX = 1_000_000_000;
type O = Record<string, unknown>;
const isObject = (v: unknown): v is O => typeof v === 'object' && v !== null && !Array.isArray(v);
const line = (v: unknown, max = 200): boolean =>
  typeof v === 'string' && v !== '' && Array.from(v).length <= max && !CONTROL.test(v) && !FORMAT.test(v) && v === v.trim();
const date = (v: unknown): v is string => {
  if (typeof v !== 'string') return false;
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v);
  if (!m) return false;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return d.getUTCFullYear() === Number(m[1]) && d.getUTCMonth() === Number(m[2]) - 1 && d.getUTCDate() === Number(m[3]);
};
const count = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= COUNT_MAX;
const only = (o: O, req: readonly string[], opt: readonly string[] = []) =>
  req.every((k) => k in o) && Object.keys(o).every((k) => req.includes(k) || opt.includes(k));
const ref = (v: unknown) => isObject(v) && only(v, ['id', 'version']) && line(v.id) && line(v.version);

const resultProblems = (kind: string, subject: unknown, r: unknown): string[] => {
  if (kind === 'retraction') return r === undefined ? [] : ['a withdrawal carries no result'];
  if (!isObject(r)) return ['result is missing'];
  const out: string[] = [];
  switch (kind) {
    case 'numbers':
      if (!only(r, ['form']) || !line(r.form)) out.push('a numbers result names its form');
      break;
    case 'pathogen':
      if (!only(r, ['target', 'sampleType', 'detected'], ['ct'])) out.push('result has the wrong fields');
      if (!line(r.target)) out.push('target is one line');
      if (!line(r.sampleType)) out.push('sampleType is one line');
      if (typeof r.detected !== 'boolean') out.push('detected is true or false');
      if (r.ct !== undefined && !(typeof r.ct === 'string' && CT.test(r.ct))) out.push('ct is a decimal under 100, two places at most');
      break;
    case 'match':
      if (!only(r, ['other', 'matches'], ['otherSampleId', 'compared', 'differing'])) out.push('result has the wrong fields');
      if (r.otherSampleId !== undefined && !line(r.otherSampleId)) out.push('otherSampleId is one line');
      if (!(typeof r.other === 'string' && HEX64.test(r.other)) || r.other === subject) out.push('other is another record’s proof code');
      if (typeof r.matches !== 'boolean') out.push('matches is true or false');
      if (r.compared !== undefined && !(count(r.compared) && r.compared >= 1)) out.push('compared is a whole number, 1 or more');
      if (r.differing !== undefined && !count(r.differing)) out.push('differing is a whole number');
      if (count(r.compared) && count(r.differing) && r.differing > r.compared) out.push('differing is at most compared');
      break;
    case 'lineage': {
      if (!only(r, ['parents', 'consistent'], ['compared', 'conflicts'])) out.push('result has the wrong fields');
      const p = r.parents;
      if (
        !Array.isArray(p) ||
        p.length < 1 ||
        p.length > 2 ||
        p.some((x) => !(typeof x === 'string' && HEX64.test(x)) || x === subject) ||
        new Set(p).size !== p.length
      )
        out.push('parents are one or two other records’ proof codes, each once');
      if (typeof r.consistent !== 'boolean') out.push('consistent is true or false');
      if (r.compared !== undefined && !(count(r.compared) && r.compared >= 1)) out.push('compared is a whole number, 1 or more');
      if (r.conflicts !== undefined) {
        const c = r.conflicts;
        if (!Array.isArray(c) || !Array.isArray(p) || c.length !== p.length || !c.every(count))
          out.push('conflicts are whole numbers, one per parent');
        else if (count(r.compared) && c.some((x) => (x as number) > (r.compared as number)))
          out.push('conflicts are at most compared');
      }
      break;
    }
    case 'dna-mark':
      if (!only(r, ['seal', 'found'], ['label'])) out.push('result has the wrong fields');
      if (!(typeof r.seal === 'string' && HEX64.test(r.seal))) out.push('seal is 64 lowercase hex characters');
      if (typeof r.found !== 'boolean') out.push('found is true or false');
      if (r.label !== undefined && (!line(r.label) || SEQUENCE_RUN.test(r.label as string)))
        out.push('label is one line, and not a run of ten or more A, C, G, T');
      break;
  }
  return out;
};

/** What is wrong with a result statement, one sentence each; [] when nothing is (SPEC 11.12). */
export const labStatementProblems = (s: unknown): string[] => {
  if (!isObject(s)) return ['a statement is an object'];
  const out: string[] = [];
  if (s.format !== LAB_RESULT_FORMAT) out.push(`format must be ${LAB_RESULT_FORMAT}`);
  if (!only(s, ['format', 'kind', 'subject', 'sampleId', 'accession', 'method', 'tested'], ['panel', 'received', 'qc', 'result', 'replaces']))
    out.push('the statement has a missing field or one it shouldn’t');
  if (!(LAB_RESULT_KINDS as readonly unknown[]).includes(s.kind)) out.push('kind is not one of the kinds');
  if (!(typeof s.subject === 'string' && HEX64.test(s.subject))) out.push('subject is 64 lowercase hex characters');
  if (!line(s.sampleId)) out.push('sampleId is one line');
  if (!line(s.accession)) out.push('accession is one line');
  if (!ref(s.method)) out.push('method is an id and a version');
  if (s.panel !== undefined && !ref(s.panel)) out.push('panel is an id and a version');
  if (!date(s.tested)) out.push('tested is a date');
  if (s.received !== undefined && !(date(s.received) && date(s.tested) && s.received <= s.tested))
    out.push('received is a date, not after tested');
  if (s.qc !== undefined) {
    const q = s.qc;
    if (
      !Array.isArray(q) ||
      q.length < 1 ||
      q.length > LAB_QC_MAX ||
      !q.every((x) => isObject(x) && only(x, ['name', 'value']) && line(x.name, 60) && line(x.value, 60)) ||
      new Set(q.map((x) => (x as O).name)).size !== q.length
    )
      out.push(`qc is 1 to ${LAB_QC_MAX} names and values, names not repeated`);
  }
  if (typeof s.kind === 'string') out.push(...resultProblems(s.kind, s.subject, s.result));
  const rep = s.replaces;
  if (rep !== undefined) {
    if (
      !isObject(rep) ||
      !only(rep, ['result', 'reason']) ||
      !(typeof rep.result === 'string' && HEX64.test(rep.result)) ||
      !(LAB_REPLACE_REASONS as readonly unknown[]).includes(rep.reason)
    )
      out.push('replaces is a result code and a reason');
  }
  const reason = isObject(rep) ? rep.reason : undefined;
  if ((s.kind === 'retraction') !== (reason === 'retraction'))
    out.push('a withdrawal, and only a withdrawal, names a result with the reason retraction');
  return out;
};

/** The file entry a record carries for a statement: its name, and the SHA-256 and size of its canonical bytes. */
export const labStatementFile = async (s: unknown): Promise<{ name: string; sha256: string; size: number }> => {
  const p = labStatementProblems(s);
  if (p.length) throw new Error(p.join('; '));
  const bytes = new TextEncoder().encode(canonicalise(s));
  return { name: LAB_RESULT_FILE_NAME, sha256: toHex(await sha256(bytes)), size: bytes.length };
};

/** The field-set numbers a statement's call makes, as decimal text or null (not for a numbers result). */
export const labCallValues = (s: O): (string | null)[] => {
  const v: (string | null)[] = Array.from({ length: 16 }, () => null);
  const r = (s.result ?? {}) as O;
  const b = (x: unknown) => (x ? '1' : '0');
  const n = (x: unknown) => (x === undefined ? null : String(x));
  switch (s.kind) {
    case 'pathogen': {
      v[0] = b(r.detected);
      if (typeof r.ct === 'string') {
        const [w, f = ''] = r.ct.split('.');
        v[1] = String(Number(w) * 100 + Number((f + '00').slice(0, 2)));
      }
      break;
    }
    case 'match':
      [v[0], v[1], v[2]] = [b(r.matches), n(r.compared), n(r.differing)];
      break;
    case 'lineage': {
      const c = r.conflicts as unknown[] | undefined;
      [v[0], v[1], v[2], v[3]] = [b(r.consistent), n(r.compared), n(c?.[0]), n(c?.[1])];
      break;
    }
    case 'dna-mark':
      v[0] = b(r.found);
      break;
    case 'retraction':
      v[0] = '1';
      break;
    default:
      throw new Error('a numbers result’s values are the laboratory’s own, under its form');
  }
  return v;
};

/**
 * What is wrong with the binding of a statement to a record (SPEC 11.12, "Binding"): the
 * record's committed fields (a document record), the field set's values (decimal text or null,
 * sixteen), and the schema documents by id. [] when it binds.
 */
export const labBindingProblems = async (input: {
  readonly fields: unknown;
  readonly statement: unknown;
  readonly values: readonly (string | null)[];
  readonly schemas: Readonly<Record<string, FieldSchema>>;
}): Promise<string[]> => {
  const { fields, statement, values, schemas } = input;
  const out = [...labStatementProblems(statement)];
  if (out.length) return out;
  out.push(...validateDocumentFields(fields));
  if (out.length) return out;
  const f = fields as O;
  const s = statement as O;
  if (f.type !== 'lab-report') out.push('type must be lab-report');
  const want = await labStatementFile(s);
  const entries = (f.files as O[]).filter((x) => x.name === LAB_RESULT_FILE_NAME);
  if (entries.length !== 1) out.push(`exactly one file is named ${LAB_RESULT_FILE_NAME}`);
  else if (entries[0].sha256 !== want.sha256 || entries[0].size !== want.size)
    out.push('the statement file’s SHA-256 or size is not the statement’s');
  if (f.issued !== s.tested) out.push('issued is the date tested');
  const about = f.about as O[];
  if (about.length !== 1 || about[0].name !== s.sampleId || about[0].recordId !== undefined)
    out.push('about names the sample ID, and only it');
  if (f.reference !== s.accession) out.push('reference is the accession number');
  if (typeof f.fieldSchema !== 'string') return [...out, 'a laboratory result carries a field set'];
  const form = s.kind === 'numbers' ? (s.result as O).form : LAB_CALL_SCHEMAS[s.kind as Exclude<LabResultKind, 'numbers'>];
  if (s.kind === 'numbers' && (Object.values(LAB_CALL_SCHEMAS) as unknown[]).includes(form))
    return [...out, 'a numbers result is not under a call form'];
  const doc = schemas[form as string];
  if (!doc) return [...out, `no schema document for ${String(form)}`];
  if (toHex(await fieldSchemaId(doc)) !== f.fieldSchema) out.push('fieldSchema is not the id of the kind’s form');
  if (!Array.isArray(values) || values.length !== 16) return [...out, 'values are sixteen'];
  if (s.kind !== 'numbers') {
    const v = labCallValues(s);
    if (v.some((x, i) => x !== values[i])) out.push('the field set’s values do not agree with the statement');
  }
  return out;
};

const MARK_TAG = new TextEncoder().encode('veilcore:dnamark:v1\0');

/** seal = SHA-256("veilcore:dnamark:v1" 0x00 || salt || sequence): a DNA mark sealed, hex (SPEC 11.12). */
export const dnaMarkSeal = async (sequence: string, saltHex: string): Promise<string> => {
  if (!/^[ACGT]{10,100000}$/.test(sequence)) throw new Error('a mark is 10 to 100,000 of A, C, G and T');
  if (!HEX64.test(saltHex)) throw new Error('the salt is 64 lowercase hex characters');
  const salt = Uint8Array.from(saltHex.match(/../g)!, (b) => parseInt(b, 16));
  const seq = new TextEncoder().encode(sequence);
  const all = new Uint8Array(MARK_TAG.length + 32 + seq.length);
  all.set(MARK_TAG);
  all.set(salt, MARK_TAG.length);
  all.set(seq, MARK_TAG.length + 32);
  return toHex(await sha256(all));
};
