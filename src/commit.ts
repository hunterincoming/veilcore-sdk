// Computing and verifying a record commitment.
//
// Plain SHA-256 over the canonical serialisation of the committed fields. No chain
// runtime, no toolchain, no dependency on us — which is the property that lets a
// registry we do not operate issue records in this format.
//
// Binding a commitment to a chain is a separate step, described by anchor.commitmentAlgorithm.
//
// SPDX-License-Identifier: Apache-2.0

import { canonicalise } from './canonical.js';
import { sha256Hex, toHex } from './hash.js';
import type { Envelope } from './types.js';
import { FIELDS_ALGORITHM, FIELD_SLOTS, FIELD_SALT_BYTES, type FieldSet, fieldRecordCommitment, fieldSetRootOf, fromHex } from './fields.js';

/**
 * The fields a commitment covers.
 *
 * `anchor` and `terms` are excluded by definition: the anchor is about the commitment
 * and cannot be inside it, and terms are issued and revoked after sealing.
 */
export const committedFields = (env: Envelope): Record<string, unknown> => ({
  // Absent means empty; an explicit null is refused by the canonicaliser (SPEC 4.4 rule 4),
  // never silently read as empty.
  attestations: env.attestations === undefined ? [] : env.attestations,
  commitmentAlgorithm: env.commitmentAlgorithm,
  extensions: env.extensions,
  fieldSchema: env.fieldSchema,
  fieldSetRoot: env.fieldSetRoot,
  formatVersion: env.formatVersion,
  holder: env.holder,
  identification: env.identification,
  jurisdictionBindings: env.jurisdictionBindings,
  ledgerIdentity: env.ledgerIdentity,
  parents: env.parents === undefined ? [] : env.parents,
  profile: env.profile,
  profileData: env.profileData,
  recordId: env.recordId,
  registrations: env.registrations,
  sealedAt: env.sealedAt,
  subject: env.subject,
  subjectType: env.subjectType,
  supersedes: env.supersedes,
});

const HEX32 = /^[0-9a-f]{64}$/;

/**
 * Compute the commitment for an envelope.
 *
 * `sha256/canonical-json/v1`: SHA-256 of the canonical JSON of the committed fields.
 * `sha256/fields/v1` (SPEC 4.5): H("veilcore:v1:frecord", fieldSetRoot, that same digest),
 * so the commitment also binds a field set whose slots can be proved one at a time. The
 * root is also inside the committed JSON, so anyone shown the JSON sees which field set
 * it belongs to and one JSON cannot be paired with two field sets.
 * Any other algorithm name is refused.
 */
/** Committed fields every record has (SPEC 3.1). A record missing one is refused, not hashed. */
const REQUIRED_COMMITTED = ['formatVersion', 'recordId', 'subjectType', 'profile', 'sealedAt', 'holder', 'profileData'] as const;

const checkLedgerIdentity = (li: unknown): void => {
  if (li === undefined) return;
  if (typeof li !== 'object' || li === null || Array.isArray(li)) throw new Error('ledgerIdentity is an object');
  const o = li as Record<string, unknown>;
  const allowed = new Set(['chain', 'contractAddress', 'identity']);
  for (const k of Object.keys(o)) if (!allowed.has(k)) throw new Error(`ledgerIdentity has an unknown field: ${k}`);
  if (typeof o.chain !== 'string' || o.chain.length === 0) throw new Error('ledgerIdentity.chain is a non-empty string');
  if (typeof o.identity !== 'string' || !HEX32.test(o.identity)) throw new Error('ledgerIdentity.identity is 64 lowercase hex characters');
  if (o.contractAddress !== undefined && (typeof o.contractAddress !== 'string' || !HEX32.test(o.contractAddress))) {
    throw new Error('ledgerIdentity.contractAddress is 64 lowercase hex characters');
  }
};

export const computeCommitment = async (env: Envelope): Promise<string> => {
  if (typeof env !== 'object' || env === null || Array.isArray(env)) throw new Error('a record is a JSON object');
  for (const k of REQUIRED_COMMITTED) {
    if ((env as Record<string, unknown>)[k] === undefined) throw new Error(`a record needs ${k}`);
  }
  checkLedgerIdentity(env.ledgerIdentity);
  if (env.commitmentAlgorithm === 'sha256/canonical-json/v1') {
    // Field-set bindings mean nothing under this algorithm, so a record carrying them is
    // refused rather than committed with a root nothing checks (attack round B-H4).
    if (env.fieldSchema !== undefined || env.fieldSetRoot !== undefined) throw new Error('fieldSchema and fieldSetRoot belong only to sha256/fields/v1 records');
    return sha256Hex(canonicalise(committedFields(env)));
  }
  if (env.commitmentAlgorithm !== FIELDS_ALGORITHM) throw new Error(`unsupported commitment algorithm: ${String(env.commitmentAlgorithm)}`);
  const jsonDigest = await sha256Hex(canonicalise(committedFields(env)));
  if (typeof env.fieldSetRoot !== 'string' || !HEX32.test(env.fieldSetRoot)) throw new Error('sha256/fields/v1 needs fieldSetRoot as 64 lowercase hex characters');
  if (typeof env.fieldSchema !== 'string' || !HEX32.test(env.fieldSchema)) throw new Error('sha256/fields/v1 needs fieldSchema as 64 lowercase hex characters');
  return toHex(await fieldRecordCommitment(fromHex(env.fieldSetRoot), fromHex(jsonDigest)));
};

/**
 * Check a holder's private field set against the record: same schema, same root. Run by
 * the holder before proving anything, and by anyone the holder shows the values to.
 */
export const verifyFieldSet = async (env: Envelope, fs: FieldSet): Promise<VerifyResult> => {
  // A verifier: malformed input is a failed check with a reason, never an exception.
  try {
    if (typeof env !== 'object' || env === null) return { valid: false, reason: 'the record is not an object' };
    if (env.commitmentAlgorithm !== FIELDS_ALGORITHM) return { valid: false, reason: 'not a sha256/fields/v1 record' };
    if (typeof env.fieldSchema !== 'string' || !HEX32.test(env.fieldSchema) || typeof env.fieldSetRoot !== 'string' || !HEX32.test(env.fieldSetRoot)) {
      return { valid: false, reason: 'the record does not carry fieldSchema and fieldSetRoot as 64 lowercase hex characters' };
    }
    const bad = fieldSetShapeError(fs);
    if (bad) return { valid: false, reason: bad };
    if (toHex(fs.schemaId) !== env.fieldSchema) return { valid: false, reason: 'the field set is under a different schema' };
    const root = toHex(await fieldSetRootOf(fs));
    return root === env.fieldSetRoot
      ? { valid: true, computed: root }
      : { valid: false, computed: root, claimed: env.fieldSetRoot, reason: 'the field set does not match the record' };
  } catch (e) {
    return { valid: false, reason: `the field set could not be checked: ${(e as Error)?.message ?? String(e)}` };
  }
};

// Bytes must be bytes. A plain array of numbers has a length and can be copied into a
// buffer, where 256 silently becomes 0: a "field set" that is not one could then match.
const isBytes = (b: unknown, n: number): boolean => b instanceof Uint8Array && b.length === n;

const fieldSetShapeError = (fs: unknown): string | undefined => {
  if (typeof fs !== 'object' || fs === null) return 'the field set is not an object';
  const f = fs as Partial<FieldSet>;
  if (!isBytes(f.schemaId, 32)) return 'the field set\'s schemaId is not 32 bytes';
  if (!Array.isArray(f.values) || f.values.length !== FIELD_SLOTS) return 'a field set has 16 values';
  if (!Array.isArray(f.salts) || f.salts.length !== FIELD_SLOTS) return 'a field set has 16 salts';
  for (let i = 0; i < FIELD_SLOTS; i++) {
    if (!isBytes(f.values[i], 32)) return `value ${i} is not 32 bytes`;
    if (!isBytes(f.salts[i], FIELD_SALT_BYTES)) return `salt ${i} is not ${FIELD_SALT_BYTES} bytes`;
  }
  return undefined;
};

export type VerifyResult = {
  valid: boolean;
  /** Present when invalid: what we computed versus what the record claims. */
  computed?: string;
  claimed?: string;
  reason?: string;
};

/**
 * Verify a record's commitment.
 *
 * This proves the record is unaltered since sealing. It does not prove the contents are
 * true — that is a separate question, answered by attestations and by the anchor's
 * timestamp, and conflating the two is how registries end up overclaiming.
 */
export const verifyCommitment = async (env: Envelope): Promise<VerifyResult> => {
  // A verifier: a malformed record is reported as not verifying, with the reason. It
  // never throws, so `if (!(await verifyCommitment(x)).valid)` is safe on anything.
  try {
    if (typeof env !== 'object' || env === null || Array.isArray(env)) return { valid: false, reason: 'a record is a JSON object' };
    if (env.commitmentAlgorithm !== 'sha256/canonical-json/v1' && env.commitmentAlgorithm !== FIELDS_ALGORITHM) {
      return { valid: false, reason: `unsupported commitment algorithm: ${String(env.commitmentAlgorithm).slice(0, 80)}` };
    }
    const computed = await computeCommitment(env);
    return computed === env.commitment
      ? { valid: true, computed }
      : { valid: false, computed, ...(typeof env.commitment === 'string' ? { claimed: env.commitment } : {}), reason: 'commitment does not match contents' };
  } catch (e) {
    return { valid: false, reason: (e as Error)?.message ?? String(e) };
  }
};
