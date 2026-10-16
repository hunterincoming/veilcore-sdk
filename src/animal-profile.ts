// Animal records: the animal-individual profile (SPEC 11.8, draft).
//
// A record under `veilcore/profile/animal-individual/v1` describes one animal. Its fingerprint
// is computed exactly as any record's (computeRecordFingerprint, SPEC 3.6.1 and 4.4): the
// profile changes no rule, it says only which fields are committed and in what form. This
// module checks that form. A record in any other form is refused, never tidied: one animal
// written two ways would seal as two different records.
//
// Vectors: conformance/vectors.json, sections animalRecords and animalRefusals, copied
// unchanged from conformance/animal-individual-v1.json (the VeilCore web application's
// contract/vectors/animal-individual-v1.json).
//
// SPDX-License-Identifier: Apache-2.0

import { computeRecordFingerprint, type RecordFingerprint } from './key-binding.js';

/** The profile id of an animal record (SPEC 11.8). */
export const ANIMAL_INDIVIDUAL_PROFILE = 'veilcore/profile/animal-individual/v1';

export type AnimalSex = 'female' | 'male' | 'unknown';

/** A sire or dam as committed: a name and an individual ID (either may be empty), and a linked record. */
export type AnimalParent = {
  role: 'sire' | 'dam';
  name: string;
  individualId: string;
  recordId?: string;
};

/** The committed fields of an animal record (SPEC 11.8). */
export type AnimalIndividualFields = {
  profile: typeof ANIMAL_INDIVIDUAL_PROFILE;
  species: string;
  breed: string;
  name: string;
  individualId: string;
  idScheme: string;
  sex: AnimalSex;
  dateOfBirth: string;
  parents: AnimalParent[];
  breeder: string;
  herd: string;
  notes: string;
  photoFingerprints: string[];
  loggedAt: number;
  nonce: string;
  keyBinding?: string;
};

/** The longest one-line value, and the longest notes, in characters. */
export const ANIMAL_LINE_MAX = 200;
export const ANIMAL_NOTES_MAX = 20_000;

const REQUIRED = [
  'breed',
  'breeder',
  'dateOfBirth',
  'herd',
  'idScheme',
  'individualId',
  'loggedAt',
  'name',
  'nonce',
  'notes',
  'parents',
  'photoFingerprints',
  'profile',
  'sex',
  'species',
];
const ALLOWED = new Set([...REQUIRED, 'keyBinding']);
const LINES = ['species', 'breed', 'name', 'individualId', 'idScheme', 'breeder', 'herd'];
const SEXES: readonly string[] = ['female', 'male', 'unknown'];
const PARENT_KEYS = new Set(['role', 'name', 'individualId', 'recordId']);
const HEX64 = /^[0-9a-f]{64}$/;
const NONCE = /^(?:[0-9a-f]{2}){32,64}$/;
const RECORD_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CONTROL = /\p{Cc}/u;

const lineProblem = (what: string, v: unknown): string | undefined => {
  if (typeof v !== 'string') return `${what} must be text`;
  if (Array.from(v).length > ANIMAL_LINE_MAX) return `${what} must be at most ${ANIMAL_LINE_MAX} characters`;
  if (CONTROL.test(v)) return `${what} must be one line, with no tabs or control characters`;
  if (v !== v.trim()) return `${what} must not start or end with a space`;
  return undefined;
};

/** A real calendar date written YYYY-MM-DD. */
export const isCalendarDate = (v: string): boolean => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v);
  if (!m) return false;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return d.getUTCFullYear() === Number(m[1]) && d.getUTCMonth() === Number(m[2]) - 1 && d.getUTCDate() === Number(m[3]);
};

const parentProblems = (parents: unknown): string[] => {
  if (!Array.isArray(parents)) return ['parents must be a list'];
  if (parents.length > 2) return ['parents may name a sire and a dam, nothing more'];
  const out: string[] = [];
  const roles: string[] = [];
  parents.forEach((p: unknown, i) => {
    const at = `parent ${i + 1}`;
    if (typeof p !== 'object' || p === null || Array.isArray(p)) {
      out.push(`${at} must be an object`);
      return;
    }
    const q = p as Record<string, unknown>;
    for (const k of Object.keys(q)) if (!PARENT_KEYS.has(k)) out.push(`${at}: ${k} is not a parent field`);
    if (q.role !== 'sire' && q.role !== 'dam') out.push(`${at}: role must be sire or dam`);
    else roles.push(q.role);
    for (const k of ['name', 'individualId']) {
      if (q[k] === undefined) out.push(`${at}: ${k} is missing`);
      else {
        const pr = lineProblem(`${at}: ${k}`, q[k]);
        if (pr) out.push(pr);
      }
    }
    if (q.recordId !== undefined && !(typeof q.recordId === 'string' && RECORD_ID.test(q.recordId)))
      out.push(`${at}: recordId is not a record id`);
    if (q.recordId === undefined && q.name === '' && q.individualId === '')
      out.push(`${at}: needs a name, an individual ID or a linked record`);
  });
  if (roles.length === 2 && roles[0] === roles[1]) out.push('parents may name one sire and one dam');
  else if (roles.length === 2 && roles[0] !== 'sire') out.push('the sire comes before the dam');
  return out;
};

/**
 * What is wrong with an animal record's committed fields, one plain sentence each; [] when
 * they are in the profile's canonical form (SPEC 11.8). Never throws.
 */
export const animalIndividualProblems = (fields: unknown): string[] => {
  if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) return ['the fields must be an object'];
  const f = fields as Record<string, unknown>;
  const out: string[] = [];
  if (f.profile !== ANIMAL_INDIVIDUAL_PROFILE) out.push(`profile must be ${ANIMAL_INDIVIDUAL_PROFILE}`);
  for (const k of REQUIRED) if (f[k] === undefined) out.push(`${k} is missing`);
  for (const k of Object.keys(f)) if (!ALLOWED.has(k)) out.push(`${k} is not a field of this profile`);
  for (const k of LINES) {
    if (f[k] === undefined) continue;
    const p = lineProblem(k, f[k]);
    if (p) out.push(p);
  }
  if (f.notes !== undefined) {
    if (typeof f.notes !== 'string') out.push('notes must be text');
    else if (Array.from(f.notes).length > ANIMAL_NOTES_MAX) out.push(`notes must be at most ${ANIMAL_NOTES_MAX} characters`);
  }
  const text = (k: string) => (typeof f[k] === 'string' ? (f[k] as string) : '');
  if (f.species !== undefined && text('species') === '') out.push('species must not be empty');
  if (f.breeder !== undefined && text('breeder') === '') out.push('breeder must not be empty');
  if (f.name !== undefined && f.individualId !== undefined && text('name') === '' && text('individualId') === '')
    out.push('a name or an individual ID is needed');
  if (text('individualId') !== '' && f.idScheme !== undefined && text('idScheme') === '')
    out.push('idScheme must say which ID scheme the individual ID belongs to');
  if (text('idScheme') !== '' && f.individualId !== undefined && text('individualId') === '')
    out.push('idScheme is given but individualId is empty');
  if (f.sex !== undefined && !SEXES.includes(f.sex as string)) out.push('sex must be female, male or unknown');
  if (f.dateOfBirth !== undefined && f.dateOfBirth !== '' && !(typeof f.dateOfBirth === 'string' && isCalendarDate(f.dateOfBirth)))
    out.push('dateOfBirth must be empty or a date written YYYY-MM-DD');
  if (f.loggedAt !== undefined && !(typeof f.loggedAt === 'number' && Number.isSafeInteger(f.loggedAt) && f.loggedAt >= 0))
    out.push('loggedAt must be a whole number of milliseconds, 0 or more');
  if (f.nonce !== undefined && !(typeof f.nonce === 'string' && NONCE.test(f.nonce)))
    out.push('nonce must be 32 to 64 bytes of lowercase hex');
  if (f.keyBinding !== undefined && !(typeof f.keyBinding === 'string' && HEX64.test(f.keyBinding)))
    out.push('keyBinding must be 64 lowercase hex characters');
  if (f.photoFingerprints !== undefined) {
    if (!Array.isArray(f.photoFingerprints) || f.photoFingerprints.length > 500)
      out.push('photoFingerprints must be a list of at most 500');
    else if (!f.photoFingerprints.every((p) => typeof p === 'string' && HEX64.test(p)))
      out.push('each photo fingerprint must be 64 lowercase hex characters');
  }
  if (f.parents !== undefined) out.push(...parentProblems(f.parents));
  return out;
};

/** Whether these fields are an animal record in the profile's canonical form. */
export const isAnimalIndividual = (fields: unknown): fields is AnimalIndividualFields =>
  animalIndividualProblems(fields).length === 0;

/**
 * The fingerprint of an animal record's committed fields, after checking their form: throws
 * the problems for fields not in the profile's form, else exactly computeRecordFingerprint.
 */
export const computeAnimalRecordFingerprint = async (fields: unknown): Promise<RecordFingerprint> => {
  const problems = animalIndividualProblems(fields);
  if (problems.length) throw new Error(`not a valid animal record: ${problems.join('; ')}`);
  return computeRecordFingerprint(fields);
};
