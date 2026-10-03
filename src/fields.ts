// Field sets: commitment algorithm `sha256/fields/v1` (SPEC 4.5).
//
// A record sealed this way commits each of 16 slots as a salted leaf under a root, so a
// holder can later prove one fact about one slot — that it holds a value, that a number
// meets a bound, that two records differ in enough slots, that a correction changed only
// some — without disclosing the rest. The proofs themselves run on Midnight (the VeilCore
// claims contract); everything here is plain SHA-256, so any implementation can seal a
// field set and check a commitment with nothing else.
//
// SPDX-License-Identifier: Apache-2.0

import { canonicalise } from './canonical.js';
import { toHex } from './hash.js';

export const FIELDS_ALGORITHM = 'sha256/fields/v1';
export const FIELD_SLOTS = 16;

const subtle = (): SubtleCrypto | undefined => (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;

const sha256 = async (bytes: Uint8Array): Promise<Uint8Array> => {
  const s = subtle();
  if (s) return new Uint8Array(await s.digest('SHA-256', bytes as BufferSource));
  const nodeCrypto = await import(/* @vite-ignore */ 'node' + ':crypto');
  return new Uint8Array(nodeCrypto.createHash('sha256').update(bytes).digest());
};

export const fromHex = (h: string): Uint8Array => {
  if (!/^[0-9a-f]*$/.test(h) || h.length % 2 !== 0) throw new Error('expected lowercase hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
};

const tag = (t: string): Uint8Array => {
  const b = new Uint8Array(32);
  const e = new TextEncoder().encode(t);
  if (e.length > 32) throw new Error(`tag too long: ${t}`);
  b.set(e);
  return b;
};

/** SHA-256 over 32-byte elements (Compact's persistentHash over Vector<n, Bytes<32>>). */
export const hashElements = async (...parts: Uint8Array[]): Promise<Uint8Array> => {
  const buf = new Uint8Array(parts.length * 32);
  parts.forEach((p, i) => {
    if (p.length !== 32) throw new Error('every element is 32 bytes');
    buf.set(p, i * 32);
  });
  return sha256(buf);
};

/** A slot value is 32 bytes. These are the three kinds. */
export const ABSENT_VALUE = new Uint8Array(32);

/** A count, mask or index as 32 bytes, little-endian. Not a slot value. */
export const countBytes = (n: bigint | number): Uint8Array => {
  const v = BigInt(n);
  if (v < 0n || v >= 1n << 64n) throw new Error('a count is 0 to 2^64 - 1');
  const b = new Uint8Array(32);
  let x = v;
  for (let i = 0; i < 8; i++) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
};

/**
 * An unsigned 64-bit integer slot value: little-endian in bytes 0-7, byte 8 set to 1 to
 * mark it present. Without the marker the number 0 and an absent slot would be the same
 * 32 bytes, and a record with no test result could prove "at most 0.3%".
 */
export const numberSlotValue = (n: bigint | number): Uint8Array => {
  const b = countBytes(n);
  b[8] = 1;
  return b;
};

/** Read a number slot value back, refusing anything that is not one. */
export const numberFromSlotValue = (v: Uint8Array): bigint => {
  if (v.length !== 32 || v[8] !== 1 || v.subarray(9).some((x) => x !== 0)) throw new Error('not a number slot value');
  let n = 0n;
  for (let i = 7; i >= 0; i--) n = (n << 8n) | BigInt(v[i]);
  return n;
};

/** A text value: SHA-256 of its UTF-8 after NFC normalisation. */
export const textSlotValue = async (text: string): Promise<Uint8Array> => {
  // An unpaired surrogate would be replaced by U+FFFD on encoding, so three different
  // strings would hash the same (the canonicaliser refuses the same input, SPEC 4.4 rule 1).
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(text)) throw new Error('text contains an unpaired surrogate');
  return sha256(new TextEncoder().encode(text.normalize('NFC')));
};

/** A 16-slot mask as a number (slot i is bit i), little-endian in 32 bytes. */
export const maskSlotValue = (mask: readonly boolean[]): Uint8Array => {
  if (mask.length !== FIELD_SLOTS) throw new Error('a mask has 16 slots');
  let n = 0n;
  mask.forEach((b, i) => {
    if (b) n |= 1n << BigInt(i);
  });
  return countBytes(n);
};

/**
 * A published field schema. `slots` names what each of the 16 slots holds; `comparable`
 * slots count towards distinctness, and `k` is the distinctness threshold. Both are part
 * of the schema id, so a claim cannot use a different k or set of slots.
 */
export type FieldSchema = {
  id: string;
  title: string;
  slots: {
    slot: number;
    path: string;
    type: 'uint' | 'text';
    unit?: string;
    scale?: number;
    comparable?: boolean;
    /** Required for a comparable text slot: the one way its values may be written. */
    format?: 'allele-pair' | 'allele' | 'code';
  }[];
  k: number;
  [extra: string]: unknown;
};

/**
 * Canonical forms for comparable text. Distinctness compares bytes, so one genotype
 * written two ways ("180/184" and "184/180") would count as a difference; a comparable
 * text slot therefore declares a format and only its canonical form is accepted.
 *   allele-pair  two allele sizes, decimal, no leading zeros, smaller first: "180/184"
 *   allele       one allele size: "233"
 *   code         upper-case letters, digits, '.', '_' or '-', starting with a letter or digit
 */
export const FIELD_FORMATS: Record<string, RegExp> = {
  'allele-pair': /^(0|[1-9][0-9]{0,8})\/(0|[1-9][0-9]{0,8})$/,
  allele: /^(0|[1-9][0-9]{0,8})$/,
  code: /^[A-Z0-9][A-Z0-9._-]{0,63}$/,
};

export const checkFormat = (format: string, text: string): void => {
  if (typeof format !== 'string' || !Object.hasOwn(FIELD_FORMATS, format)) throw new Error(`unknown format: ${String(format)}`);
  const re = FIELD_FORMATS[format];
  if (!re.test(text)) throw new Error(`not in ${format} form: ${JSON.stringify(text)}`);
  if (format === 'allele-pair') {
    const [a, b] = text.split('/').map(Number);
    if (a > b) throw new Error(`an allele pair is written smaller first: ${JSON.stringify(text)}`);
  }
};

export const schemaDocumentDigest = async (schema: FieldSchema): Promise<Uint8Array> =>
  sha256(new TextEncoder().encode(canonicalise(schema)));

/** Check a schema document and return its comparable and numeric masks. */
export const schemaMasks = (schema: FieldSchema): { comparable: boolean[]; numeric: boolean[] } => {
  if (!schema || typeof schema !== 'object' || !Array.isArray(schema.slots)) throw new Error('a schema lists its slots');
  if (typeof schema.id !== 'string' || schema.id.length === 0) throw new Error('a schema has an id');
  if (typeof schema.title !== 'string') throw new Error('a schema has a title');
  const comparable = Array.from({ length: FIELD_SLOTS }, () => false);
  const numeric = Array.from({ length: FIELD_SLOTS }, () => false);
  const seen = new Set<number>();
  for (const s of schema.slots) {
    if (!s || typeof s !== 'object') throw new Error('a slot entry is an object');
    if (!Number.isInteger(s.slot) || s.slot < 0 || s.slot >= FIELD_SLOTS) throw new Error(`slot out of range: ${String(s.slot)}`);
    if (seen.has(s.slot)) throw new Error(`slot ${s.slot} is listed twice`);
    seen.add(s.slot);
    if (s.type !== 'uint' && s.type !== 'text') throw new Error(`slot ${s.slot} has an unknown type`);
    if (typeof s.path !== 'string' || s.path.length === 0) throw new Error(`slot ${s.slot} has no path`);
    if (s.unit !== undefined && typeof s.unit !== 'string') throw new Error(`slot ${s.slot}: unit is a string`);
    if (s.scale !== undefined && (!Number.isInteger(s.scale) || s.scale < 1)) throw new Error(`slot ${s.slot}: scale is a positive integer`);
    if (s.comparable !== undefined && typeof s.comparable !== 'boolean') throw new Error(`slot ${s.slot}: comparable is true or false`);
    if (s.format !== undefined && (s.type !== 'text' || typeof s.format !== 'string' || !Object.hasOwn(FIELD_FORMATS, s.format))) throw new Error(`slot ${s.slot}: format is allele-pair, allele or code, on a text slot`);
    if (s.comparable && s.type === 'text' && s.format === undefined) throw new Error(`slot ${s.slot}: a comparable text slot declares a format`);
    if (s.comparable) comparable[s.slot] = true;
    if (s.type === 'uint') numeric[s.slot] = true;
  }
  return { comparable, numeric };
};

export const comparableMask = (schema: FieldSchema): boolean[] => schemaMasks(schema).comparable;

/**
 * schemaId = H("veilcore:v1:fschema", SHA-256(canonical schema), comparable mask, count(k),
 * numeric mask). The masks and k are inside the id so a claim cannot choose them, and the
 * numeric mask lets the claims contract refuse a range claim on a slot that is not a number.
 */
export const fieldSchemaId = async (schema: FieldSchema): Promise<Uint8Array> => {
  const { comparable, numeric } = schemaMasks(schema);
  if (!Number.isInteger(schema.k) || schema.k < 1 || schema.k > FIELD_SLOTS) throw new Error('k is 1 to 16');
  if (comparable.filter(Boolean).length < schema.k) throw new Error('k is more than the number of comparable slots');
  return hashElements(tag('veilcore:v1:fschema'), await schemaDocumentDigest(schema), maskSlotValue(comparable), countBytes(schema.k), maskSlotValue(numeric));
};

export const fieldSalt = async (fieldSecret: Uint8Array, slot: number): Promise<Uint8Array> =>
  hashElements(tag('veilcore:v1:fsalt'), fieldSecret, countBytes(slot));

export const fieldLeaf = (value: Uint8Array, salt: Uint8Array): Promise<Uint8Array> =>
  hashElements(tag('veilcore:v1:field'), value, salt);

export const fieldNode = (l: Uint8Array, r: Uint8Array): Promise<Uint8Array> => hashElements(tag('veilcore:v1:fnode'), l, r);

export const fieldSetRoot = (schemaId: Uint8Array, tree: Uint8Array): Promise<Uint8Array> =>
  hashElements(tag('veilcore:v1:fset'), schemaId, tree);

export const fieldRecordCommitment = (setRoot: Uint8Array, jsonDigest: Uint8Array): Promise<Uint8Array> =>
  hashElements(tag('veilcore:v1:frecord'), setRoot, jsonDigest);

/** The holder's private field set. Never disclosed with the record. */
export type FieldSet = {
  schemaId: Uint8Array;
  values: Uint8Array[];
  salts: Uint8Array[];
};

/**
 * Seal 16 slot values under a schema. `fieldSecret` is 32 random bytes kept with the
 * holder's private copy, never in the disclosed record: anyone who could derive the
 * salts could guess low-entropy hidden values back.
 */
export const sealFieldSet = async (schemaId: Uint8Array, values: readonly Uint8Array[], fieldSecret: Uint8Array): Promise<FieldSet> => {
  if (values.length !== FIELD_SLOTS) throw new Error('a field set has 16 slots');
  if (fieldSecret.length !== 32) throw new Error('the field secret is 32 bytes');
  values.forEach((v) => {
    if (v.length !== 32) throw new Error('every slot value is 32 bytes');
  });
  const salts = await Promise.all(values.map((_, i) => fieldSalt(fieldSecret, i)));
  return { schemaId, values: values.map((v) => new Uint8Array(v)), salts };
};

const levels = async (fs: FieldSet): Promise<Uint8Array[][]> => {
  const out: Uint8Array[][] = [await Promise.all(fs.values.map((v, i) => fieldLeaf(v, fs.salts[i])))];
  while (out[out.length - 1].length > 1) {
    const prev = out[out.length - 1];
    const next: Uint8Array[] = [];
    for (let i = 0; i < prev.length; i += 2) next.push(await fieldNode(prev[i], prev[i + 1]));
    out.push(next);
  }
  return out;
};

/** The public root of a field set. Reveals nothing about the values. */
export const fieldSetRootOf = async (fs: FieldSet): Promise<Uint8Array> => fieldSetRoot(fs.schemaId, (await levels(fs))[4][0]);

/** One slot, opened: what the claims contract needs to prove a value or a range. */
export type SlotOpening = {
  value: Uint8Array;
  salt: Uint8Array;
  siblings: Uint8Array[];
  bits: boolean[];
};

export const openFieldSlot = async (fs: FieldSet, slot: number): Promise<SlotOpening> => {
  if (!Number.isInteger(slot) || slot < 0 || slot >= FIELD_SLOTS) throw new Error('slot is 0 to 15');
  const lv = await levels(fs);
  const siblings: Uint8Array[] = [];
  const bits: boolean[] = [];
  let i = slot;
  for (let level = 0; level < 4; level++) {
    bits.push((i & 1) === 1);
    siblings.push(lv[level][i ^ 1]);
    i >>= 1;
  }
  return { value: fs.values[slot], salt: fs.salts[slot], siblings, bits };
};

/** Recompute the set root from one opened slot (what a verifier of an opening does). */
export const rootFromOpening = async (schemaId: Uint8Array, o: SlotOpening): Promise<Uint8Array> => {
  let h = await fieldLeaf(o.value, o.salt);
  for (let level = 0; level < 4; level++) h = o.bits[level] ? await fieldNode(o.siblings[level], h) : await fieldNode(h, o.siblings[level]);
  return fieldSetRoot(schemaId, h);
};

export const hex = toHex;

/** A slot value as written in a record's private copy and in the conformance vectors. */
export type TypedSlotValue = { uint: string } | { text: string } | null;

/** Turn a typed value into its 32 bytes (SPEC 4.5). */
export const slotValueOf = async (v: TypedSlotValue): Promise<Uint8Array> => {
  if (v === null) return new Uint8Array(ABSENT_VALUE);
  if (typeof v !== 'object') throw new Error('a slot value is {uint}, {text} or null');
  const keys = Object.keys(v);
  if (keys.length !== 1) throw new Error('a slot value has exactly one of uint or text');
  if ('uint' in v) {
    if (typeof v.uint !== 'string' || !/^(0|[1-9][0-9]*)$/.test(v.uint)) throw new Error('uint is a decimal string with no leading zeros');
    return numberSlotValue(BigInt(v.uint));
  }
  if ('text' in v) {
    if (typeof v.text !== 'string') throw new Error('text is a string');
    return textSlotValue(v.text);
  }
  throw new Error('a slot value is {uint}, {text} or null');
};

/**
 * Each value must match its slot's declared type, and a slot the schema does not describe
 * must be empty: otherwise a text hash could sit in a number slot and a range claim would
 * run over it.
 */
export const typedSlotValues = async (schema: FieldSchema, values: readonly TypedSlotValue[]): Promise<Uint8Array[]> => {
  schemaMasks(schema); // validates the slot list
  const typeOf = new Map(schema.slots.map((s) => [s.slot, s.type]));
  const formatOf = new Map(schema.slots.map((s) => [s.slot, s.format]));
  return Promise.all(
    values.map(async (v, i) => {
      if (v !== null && typeof v === 'object') {
        const kind = 'uint' in v ? 'uint' : 'text' in v ? 'text' : undefined;
        if (!typeOf.has(i)) throw new Error(`slot ${i} is not described by the schema, so it must be empty`);
        if (kind !== typeOf.get(i)) throw new Error(`slot ${i} holds ${typeOf.get(i)} values`);
        const format = formatOf.get(i);
        if (format !== undefined) checkFormat(format, (v as { text: string }).text);
      }
      return slotValueOf(v);
    }),
  );
};

/**
 * Seal typed values under a schema and report everything public or checkable: what the
 * conformance vectors compare across implementations.
 */
export const fieldSetSummary = async (input: {
  schema: FieldSchema;
  values: TypedSlotValue[];
  fieldSecret: string;
  open?: number[];
}): Promise<{
  schemaDocumentDigest: string;
  schemaId: string;
  slotValues: string[];
  salts: string[];
  setRoot: string;
  openings: { slot: number; siblings: string[]; bits: boolean[] }[];
}> => {
  if (!Array.isArray(input.values) || input.values.length !== FIELD_SLOTS) throw new Error('a field set has 16 slots');
  if (typeof input.fieldSecret !== 'string' || !/^[0-9a-f]{64}$/.test(input.fieldSecret)) throw new Error('fieldSecret is 64 lowercase hex characters');
  const schemaId = await fieldSchemaId(input.schema);
  const values = await typedSlotValues(input.schema, input.values);
  const fs = await sealFieldSet(schemaId, values, fromHex(input.fieldSecret));
  const openings = await Promise.all(
    (input.open ?? []).map(async (slot) => {
      const o = await openFieldSlot(fs, slot);
      return { slot, siblings: o.siblings.map(toHex), bits: o.bits };
    }),
  );
  return {
    schemaDocumentDigest: toHex(await schemaDocumentDigest(input.schema)),
    schemaId: toHex(schemaId),
    slotValues: values.map(toHex),
    salts: fs.salts.map(toHex),
    setRoot: toHex(await fieldSetRootOf(fs)),
    openings,
  };
};
