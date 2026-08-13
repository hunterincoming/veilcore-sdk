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
import { sha256Hex } from './hash.js';
import type { Envelope } from './types.js';

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

/** Compute the commitment for an envelope. */
export const computeCommitment = async (env: Envelope): Promise<string> =>
  sha256Hex(canonicalise(committedFields(env)));

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
  if (env.commitmentAlgorithm !== 'sha256/canonical-json/v1') {
    return { valid: false, reason: `unsupported commitment algorithm: ${env.commitmentAlgorithm}` };
  }
  const computed = await computeCommitment(env);
  return computed === env.commitment
    ? { valid: true, computed }
    : { valid: false, computed, claimed: env.commitment, reason: 'commitment does not match contents' };
};
