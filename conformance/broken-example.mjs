// A deliberately non-conformant implementation.
//
// Exists to prove the conformance suite detects failure. A suite that only ever passes
// is a suite that proves nothing — this is the control.
//
// The bug is subtle on purpose: plain JSON.stringify without sorted keys. It produces
// correct-looking output for records whose fields happen to be in the right order, and
// silently wrong commitments for everything else. Exactly the failure mode
// canonicalisation exists to prevent.
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';

export const canonicalise = (v) => JSON.stringify(v);

export const computeCommitment = async (env) => {
  const committed = {
    formatVersion: env.formatVersion,
    recordId: env.recordId,
    subjectType: env.subjectType,
    profile: env.profile,
    commitmentAlgorithm: env.commitmentAlgorithm,
    sealedAt: env.sealedAt,
    holder: env.holder,
    parents: env.parents ?? [],
    attestations: env.attestations ?? [],
    profileData: env.profileData,
  };
  return createHash('sha256').update(canonicalise(committed), 'utf8').digest('hex');
};
