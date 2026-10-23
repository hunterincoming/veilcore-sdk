// Strain and line records: the strain profile (SPEC 11.9, draft).
//
// A record under `veilcore/profile/strain/v1` describes one microbial strain, cell line or
// insect line. Its fingerprint is computed exactly as any record's (computeRecordFingerprint,
// SPEC 3.6.1 and 4.4): the profile changes no rule, it says only which fields are committed and
// in what form. This module checks that form. A record in any other form is refused, never
// tidied: one strain written two ways would seal as two different records.
//
// Vectors: conformance/vectors.json, sections strainRecords and strainRefusals, copied
// unchanged from conformance/strain-v1.json (the VeilCore web application's
// contract/vectors/strain-v1.json).
//
// SPDX-License-Identifier: Apache-2.0

import { computeRecordFingerprint, type RecordFingerprint } from './key-binding.js';

/** The profile id of a strain or line record (SPEC 11.9). */
export const STRAIN_PROFILE = 'veilcore/profile/strain/v1';

export const STRAIN_GROUPS = [
  'bacterium',
  'archaeon',
  'yeast',
  'filamentous-fungus',
  'microalga',
  'protist',
  'virus',
  'cell-line',
  'insect',
  'other',
] as const;
export type StrainGroup = (typeof STRAIN_GROUPS)[number];

// ---- validation (the profile's canonical form) ---------------------------------------------

export const STRAIN_LINE_MAX = 200;
export const STRAIN_NOTES_MAX = 20_000;
export const STRAIN_DEPOSITS_MAX = 8;

const REQUIRED = [
  'deposits',
  'designation',
  'generation',
  'group',
  'loggedAt',
  'madeOn',
  'maker',
  'method',
  'name',
  'nonce',
  'notes',
  'parents',
  'photoFingerprints',
  'profile',
  'species',
] as const;
const ALLOWED = new Set<string>([...REQUIRED, 'keyBinding']);
const LINES = ['species', 'name', 'designation', 'method', 'generation', 'maker'] as const;

const HEX64 = /^[0-9a-f]{64}$/;
const NONCE = /^(?:[0-9a-f]{2}){32,64}$/;
const RECORD_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CONTROL = /\p{Cc}/u;

const lineProblem = (what: string, v: unknown): string | undefined => {
  if (typeof v !== 'string') return `${what} must be text`;
  if (Array.from(v).length > STRAIN_LINE_MAX) return `${what} must be at most ${STRAIN_LINE_MAX} characters`;
  if (CONTROL.test(v)) return `${what} must be one line, with no tabs or control characters`;
  if (v !== v.trim()) return `${what} must not start or end with a space`;
  return undefined;
};

const isCalendarDate = (v: string): boolean => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v);
  if (!m) return false;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return d.getUTCFullYear() === Number(m[1]) && d.getUTCMonth() === Number(m[2]) - 1 && d.getUTCDate() === Number(m[3]);
};

/** What is wrong with a strain record's sealed fields, one sentence each; [] when none. */
export const strainProblems = (fields: unknown): string[] => {
  if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) return ['the fields must be an object'];
  const f = fields as Record<string, unknown>;
  const out: string[] = [];
  if (f.profile !== STRAIN_PROFILE) out.push(`profile must be ${STRAIN_PROFILE}`);
  for (const k of REQUIRED) if (f[k] === undefined) out.push(`${k} is missing`);
  for (const k of Object.keys(f)) if (!ALLOWED.has(k)) out.push(`${k} is not a field of this profile`);
  for (const k of LINES) {
    if (f[k] === undefined) continue;
    const p = lineProblem(k, f[k]);
    if (p) out.push(p);
  }
  const text = (k: string) => (typeof f[k] === 'string' ? f[k] : '');
  if (f.species !== undefined && text('species') === '') out.push('species must not be empty');
  if (f.maker !== undefined && text('maker') === '') out.push('maker must not be empty');
  if (f.name !== undefined && f.designation !== undefined && text('name') === '' && text('designation') === '')
    out.push('a name or a designation is needed');
  if (f.group !== undefined && !(STRAIN_GROUPS as readonly unknown[]).includes(f.group))
    out.push(`group must be one of ${STRAIN_GROUPS.join(', ')}`);
  if (f.deposits !== undefined) {
    if (!Array.isArray(f.deposits) || f.deposits.length > STRAIN_DEPOSITS_MAX)
      out.push(`deposits must be a list of at most ${STRAIN_DEPOSITS_MAX}`);
    else {
      f.deposits.forEach((d: unknown, i) => {
        const p = lineProblem(`deposit ${i + 1}`, d);
        if (p) out.push(p);
        else if (d === '') out.push(`deposit ${i + 1} must not be empty`);
      });
      if (new Set(f.deposits).size !== f.deposits.length) out.push('each deposit is listed once');
    }
  }
  if (f.notes !== undefined) {
    if (typeof f.notes !== 'string') out.push('notes must be text');
    else if (Array.from(f.notes).length > STRAIN_NOTES_MAX)
      out.push(`notes must be at most ${STRAIN_NOTES_MAX} characters`);
  }
  if (f.madeOn !== undefined && f.madeOn !== '' && !(typeof f.madeOn === 'string' && isCalendarDate(f.madeOn)))
    out.push('madeOn must be empty or a date written YYYY-MM-DD');
  if (
    f.loggedAt !== undefined &&
    !(typeof f.loggedAt === 'number' && Number.isSafeInteger(f.loggedAt) && f.loggedAt >= 0)
  )
    out.push('loggedAt must be a whole number of milliseconds, 0 or more');
  if (f.nonce !== undefined && !(typeof f.nonce === 'string' && NONCE.test(f.nonce)))
    out.push('nonce must be 32 to 64 bytes of lowercase hex');
  if (f.keyBinding !== undefined && !(typeof f.keyBinding === 'string' && HEX64.test(f.keyBinding)))
    out.push('keyBinding must be 64 lowercase hex characters');
  if (f.photoFingerprints !== undefined) {
    if (!Array.isArray(f.photoFingerprints) || f.photoFingerprints.length > 500)
      out.push('photoFingerprints must be a list of at most 500');
    else if (!f.photoFingerprints.every((p) => typeof p === 'string' && HEX64.test(p)))
      out.push('each photo code must be 64 lowercase hex characters');
  }
  if (f.parents !== undefined) out.push(...parentProblems(f.parents));
  return out;
};

const PARENT_KEYS = new Set(['name', 'deposit', 'recordId']);

/** At most two parent strains (one for a mutant or a subculture; two for a cross, fusion or mating). */
const parentProblems = (parents: unknown): string[] => {
  if (!Array.isArray(parents)) return ['parents must be a list'];
  if (parents.length > 2) return ['parents may name at most two parent strains'];
  const out: string[] = [];
  parents.forEach((p: unknown, i) => {
    const at = `parent ${i + 1}`;
    if (typeof p !== 'object' || p === null || Array.isArray(p)) {
      out.push(`${at} must be an object`);
      return;
    }
    const q = p as Record<string, unknown>;
    for (const k of Object.keys(q)) if (!PARENT_KEYS.has(k)) out.push(`${at}: ${k} is not a parent field`);
    for (const k of ['name', 'deposit'] as const) {
      if (q[k] === undefined) out.push(`${at}: ${k} is missing`);
      else {
        const pr = lineProblem(`${at}: ${k}`, q[k]);
        if (pr) out.push(pr);
      }
    }
    if (q.recordId !== undefined && !(typeof q.recordId === 'string' && RECORD_ID.test(q.recordId)))
      out.push(`${at}: recordId is not a record id`);
    if (q.recordId === undefined && q.name === '' && q.deposit === '')
      out.push(`${at}: needs a name, a deposit number or a linked record`);
  });
  return out;
};

/** Whether these fields are a strain record in the profile's canonical form. */
export const isStrainRecord = (fields: unknown): boolean => strainProblems(fields).length === 0;

/**
 * The fingerprint of a strain record's committed fields, after checking their form: throws the
 * problems for fields not in the profile's form, else exactly computeRecordFingerprint.
 */
export const computeStrainRecordFingerprint = async (fields: unknown): Promise<RecordFingerprint> => {
  const problems = strainProblems(fields);
  if (problems.length) throw new Error(`not a valid strain record: ${problems.join('; ')}`);
  return computeRecordFingerprint(fields);
};
