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
import { FIELDS_ALGORITHM, type FieldSet, fieldRecordCommitment, fieldSetRootOf, fromHex } from './fields.js';

/**
 * The fields a commitment covers.
 *
 * `anchor` and `terms` are excluded by definition: the anchor is about the commitment
 * and cannot be inside it, and terms are issued and revoked after sealing.
 */
export const committedFields = (env: Envelope): Record<string, unknown> => ({
  attestations: env.attestations ?? [],
  commitmentAlgorithm: env.commitmentAlgorithm,
  extensions: env.extensions,
  fieldSchema: env.fieldSchema,
  formatVersion: env.formatVersion,
  holder: env.holder,
  identification: env.identification,
  jurisdictionBindings: env.jurisdictionBindings,
  parents: env.parents ?? [],
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
 * so the commitment also binds a field set whose slots can be proved one at a time.
 */
export const computeCommitment = async (env: Envelope): Promise<string> => {
  const jsonDigest = await sha256Hex(canonicalise(committedFields(env)));
  if (env.commitmentAlgorithm !== FIELDS_ALGORITHM) return jsonDigest;
  if (typeof env.fieldSetRoot !== 'string' || !HEX32.test(env.fieldSetRoot)) throw new Error('sha256/fields/v1 needs fieldSetRoot as 64 lowercase hex characters');
  if (typeof env.fieldSchema !== 'string' || !HEX32.test(env.fieldSchema)) throw new Error('sha256/fields/v1 needs fieldSchema as 64 lowercase hex characters');
  return toHex(await fieldRecordCommitment(fromHex(env.fieldSetRoot), fromHex(jsonDigest)));
};

/**
 * Check a holder's private field set against the record: same schema, same root. Run by
 * the holder before proving anything, and by anyone the holder shows the values to.
 */
export const verifyFieldSet = async (env: Envelope, fs: FieldSet): Promise<VerifyResult> => {
  if (env.commitmentAlgorithm !== FIELDS_ALGORITHM) return { valid: false, reason: 'not a sha256/fields/v1 record' };
  if (toHex(fs.schemaId) !== env.fieldSchema) return { valid: false, reason: 'the field set is under a different schema' };
  const root = toHex(await fieldSetRootOf(fs));
  return root === env.fieldSetRoot
    ? { valid: true, computed: root }
    : { valid: false, computed: root, claimed: env.fieldSetRoot, reason: 'the field set does not match the record' };
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
  if (env.commitmentAlgorithm !== 'sha256/canonical-json/v1' && env.commitmentAlgorithm !== FIELDS_ALGORITHM) {
    return { valid: false, reason: `unsupported commitment algorithm: ${env.commitmentAlgorithm}` };
  }
  let computed: string;
  try {
    computed = await computeCommitment(env);
  } catch (e) {
    return { valid: false, reason: (e as Error).message };
  }
  return computed === env.commitment
    ? { valid: true, computed }
    : { valid: false, computed, claimed: env.commitment, reason: 'commitment does not match contents' };
};
