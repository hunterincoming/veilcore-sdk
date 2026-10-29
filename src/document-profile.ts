// Document records (SPEC 11.11, draft): a permit, a certificate of analysis, a contract, a
// protocol, a transport document, sealed by the SHA-256, name and size of each of its files. The
// file's bytes are never in the record. Ported from the VeilCore web application's
// document-profile.ts; checked against conformance/document-v1.json, made without either
// implementation's code.
//
// The fingerprint rules don't change (SPEC 3.6.1, 4.4): the profile says which fields are
// committed and in what form, and fields in any other form are refused, never tidied.
// SPDX-License-Identifier: Apache-2.0

import { computeRecordFingerprint, type RecordFingerprint } from './key-binding.js';

/** The profile a document record is sealed under. */
export const DOCUMENT_PROFILE = 'veilcore/profile/document/v1';

export const DOCUMENT_TYPES = [
  'permit',
  'certificate-of-analysis',
  'lab-report',
  'contract',
  'protocol',
  'transport',
  'invoice',
  'other',
] as const;
export type DocumentType = (typeof DOCUMENT_TYPES)[number];

/** One file of a document: what is sealed about it. Never its bytes. */
export type DocumentFile = {
  readonly name: string;
  /** SHA-256 of the file's bytes, 64 lowercase hex characters. */
  readonly sha256: string;
  /** Its size in bytes. */
  readonly size: number;
};

/** A genetic record the document is about: logged (recordId) or named. */
export type DocumentAbout = { readonly name: string; readonly recordId?: string };

/** What a document record has that a plant record doesn't. */
export type DocumentDetails = {
  readonly type: DocumentType;
  /** Who issued it, as written on it. '' when not stated. */
  readonly issuer: string;
  readonly files: readonly DocumentFile[];
  readonly about: readonly DocumentAbout[];
};

// ---- validation (the profile's canonical form) ---------------------------------------------

export const DOCUMENT_LINE_MAX = 200;
export const DOCUMENT_NOTES_MAX = 20_000;
export const DOCUMENT_FILES_MAX = 20;
export const DOCUMENT_ABOUT_MAX = 20;

const REQUIRED = [
  'about',
  'files',
  'holder',
  'issued',
  'issuer',
  'loggedAt',
  'nonce',
  'notes',
  'profile',
  'reference',
  'title',
  'type',
] as const;
const ALLOWED = new Set<string>([...REQUIRED, 'keyBinding']);
const LINES = ['title', 'issuer', 'reference', 'holder'] as const;

const HEX64 = /^[0-9a-f]{64}$/;
const NONCE = /^(?:[0-9a-f]{2}){32,64}$/;
const RECORD_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CONTROL = /\p{Cc}/u;

const lineProblem = (what: string, v: unknown): string | undefined => {
  if (typeof v !== 'string') return `${what} must be text`;
  if (Array.from(v).length > DOCUMENT_LINE_MAX) return `${what} must be at most ${DOCUMENT_LINE_MAX} characters`;
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

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

const FILE_KEYS = new Set(['name', 'sha256', 'size']);
const fileProblems = (files: unknown): string[] => {
  if (!Array.isArray(files)) return ['files must be a list'];
  if (files.length < 1) return ['a document needs at least one file'];
  if (files.length > DOCUMENT_FILES_MAX) return [`files may list at most ${DOCUMENT_FILES_MAX}`];
  const out: string[] = [];
  files.forEach((f: unknown, i) => {
    const at = `file ${i + 1}`;
    if (!isObject(f)) {
      out.push(`${at} must be an object`);
      return;
    }
    for (const k of Object.keys(f)) if (!FILE_KEYS.has(k)) out.push(`${at}: ${k} is not a file field`);
    if (f.name === undefined) out.push(`${at}: name is missing`);
    else {
      const p = lineProblem(`${at}: name`, f.name);
      if (p) out.push(p);
      else if (f.name === '') out.push(`${at}: name must not be empty`);
    }
    if (!(typeof f.sha256 === 'string' && HEX64.test(f.sha256)))
      out.push(`${at}: sha256 must be 64 lowercase hex characters`);
    if (!(typeof f.size === 'number' && Number.isSafeInteger(f.size) && f.size >= 0))
      out.push(`${at}: size must be a whole number of bytes, 0 or more`);
  });
  const shas = files.map((f: unknown) => (isObject(f) ? f.sha256 : undefined));
  if (new Set(shas).size !== shas.length) out.push('each file is listed once (no two with the same SHA-256)');
  return out;
};

const ABOUT_KEYS = new Set(['name', 'recordId']);
const aboutProblems = (about: unknown): string[] => {
  if (!Array.isArray(about)) return ['about must be a list'];
  if (about.length > DOCUMENT_ABOUT_MAX) return [`about may name at most ${DOCUMENT_ABOUT_MAX} records`];
  const out: string[] = [];
  about.forEach((a: unknown, i) => {
    const at = `about ${i + 1}`;
    if (!isObject(a)) {
      out.push(`${at} must be an object`);
      return;
    }
    for (const k of Object.keys(a)) if (!ABOUT_KEYS.has(k)) out.push(`${at}: ${k} is not an about field`);
    if (a.name === undefined) out.push(`${at}: name is missing`);
    else {
      const p = lineProblem(`${at}: name`, a.name);
      if (p) out.push(p);
    }
    if (a.recordId !== undefined && !(typeof a.recordId === 'string' && RECORD_ID.test(a.recordId)))
      out.push(`${at}: recordId is not a record id`);
    if (a.recordId === undefined && a.name === '') out.push(`${at}: needs a name or a linked record`);
  });
  return out;
};

/** What is wrong with a document record's sealed fields, one sentence each; [] when none. */
export const validateDocumentFields = (fields: unknown): string[] => {
  if (!isObject(fields)) return ['the fields must be an object'];
  const f = fields;
  const out: string[] = [];
  if (f.profile !== DOCUMENT_PROFILE) out.push(`profile must be ${DOCUMENT_PROFILE}`);
  for (const k of REQUIRED) if (f[k] === undefined) out.push(`${k} is missing`);
  for (const k of Object.keys(f)) if (!ALLOWED.has(k)) out.push(`${k} is not a field of this profile`);
  for (const k of LINES) {
    if (f[k] === undefined) continue;
    const p = lineProblem(k, f[k]);
    if (p) out.push(p);
  }
  if (f.title === '') out.push('title must not be empty');
  if (f.holder === '') out.push('holder must not be empty');
  if (f.type !== undefined && !(DOCUMENT_TYPES as readonly unknown[]).includes(f.type))
    out.push(`type must be one of ${DOCUMENT_TYPES.join(', ')}`);
  if (f.files !== undefined) out.push(...fileProblems(f.files));
  if (f.about !== undefined) out.push(...aboutProblems(f.about));
  if (f.notes !== undefined) {
    if (typeof f.notes !== 'string') out.push('notes must be text');
    else if (Array.from(f.notes).length > DOCUMENT_NOTES_MAX)
      out.push(`notes must be at most ${DOCUMENT_NOTES_MAX} characters`);
  }
  if (f.issued !== undefined && f.issued !== '' && !(typeof f.issued === 'string' && isCalendarDate(f.issued)))
    out.push('issued must be empty or a date written YYYY-MM-DD');
  if (
    f.loggedAt !== undefined &&
    !(typeof f.loggedAt === 'number' && Number.isSafeInteger(f.loggedAt) && f.loggedAt >= 0)
  )
    out.push('loggedAt must be a whole number of milliseconds, 0 or more');
  if (f.nonce !== undefined && !(typeof f.nonce === 'string' && NONCE.test(f.nonce)))
    out.push('nonce must be 32 to 64 bytes of lowercase hex');
  if (f.keyBinding !== undefined && !(typeof f.keyBinding === 'string' && HEX64.test(f.keyBinding)))
    out.push('keyBinding must be 64 lowercase hex characters');
  return out;
};

/** Whether these fields are a document record in the profile's canonical form. */
export const isDocumentRecord = (fields: unknown): boolean => validateDocumentFields(fields).length === 0;

/** What is wrong with a document record's committed fields; [] when nothing is. */
export const documentProblems = (fields: unknown): string[] => validateDocumentFields(fields);

/**
 * The fingerprint of a document record's committed fields, after checking their form: throws the
 * problems for fields not in the profile's form, else exactly computeRecordFingerprint.
 */
export const computeDocumentRecordFingerprint = async (fields: unknown): Promise<RecordFingerprint> => {
  const problems = validateDocumentFields(fields);
  if (problems.length) throw new Error(`not a valid document record: ${problems.join('; ')}`);
  return computeRecordFingerprint(fields);
};
