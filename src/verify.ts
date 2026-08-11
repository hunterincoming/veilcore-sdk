// Verifying a record against a registry.
//
// computeCommitment proves a record is unaltered. It does not tell you whether the
// record is real, whether it is anchored, or whether it carries an obligation — those
// are questions for the registry that holds it.
//
// This is deliberately the only part of the SDK that talks to a network, and it takes
// the registry URL as an argument. A verifier can point at any registry, including one
// we do not operate, which is the whole point of the format.
//
// SPDX-License-Identifier: Apache-2.0

import { verifyCommitment } from './commit.js';
import type { Envelope } from './types.js';

export type RegistryVerdict = {
  /** Is the record unaltered since sealing? Computed locally, no network needed. */
  intact: boolean;
  /** Does the registry hold this record? */
  known?: boolean;
  /** Does the registry's copy match the one you were handed? */
  matchesRegistry?: boolean;
  /** Is it free of unmet obligations through its declared ancestry? */
  cleanDescent?: boolean;
  /** Why a check failed, in words a non-technical holder can act on. */
  reasons: string[];
};

/**
 * Verify a record you were handed against the registry that issued it.
 *
 * The local check runs first and always: a tampered record is rejected without asking
 * anyone. Only then is the registry consulted, and a registry being unreachable is
 * reported rather than treated as a pass.
 */
export const verifyAgainstRegistry = async (
  env: Envelope,
  registryUrl: string,
  opts: { chain?: string[] } = {},
): Promise<RegistryVerdict> => {
  const reasons: string[] = [];

  const local = await verifyCommitment(env);
  if (!local.valid) {
    return { intact: false, reasons: [local.reason ?? 'commitment does not match contents'] };
  }

  const base = registryUrl.replace(/\/$/, '');
  const verdict: RegistryVerdict = { intact: true, reasons };

  try {
    const res = await fetch(`${base}/verify/${encodeURIComponent(env.recordId)}`);
    if (res.status === 404) {
      verdict.known = false;
      reasons.push('the registry does not hold a record with this identifier');
      return verdict;
    }
    const remote = await res.json();
    verdict.known = Boolean(remote?.found);
    verdict.matchesRegistry = remote?.recordFingerprint === env.commitment;
    if (!verdict.matchesRegistry) {
      reasons.push('the registry holds a different version of this record');
    }
  } catch {
    reasons.push('the registry could not be reached — the local integrity check still passed');
    return verdict;
  }

  try {
    const res = await fetch(`${base}/lineage/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ record: env.commitment, chain: opts.chain ?? [] }),
    });
    const descent = await res.json();
    verdict.cleanDescent = Boolean(descent?.ok);
    if (!descent?.ok && descent?.reason) reasons.push(descent.reason);
  } catch {
    reasons.push('clean-descent could not be checked');
  }

  return verdict;
};
