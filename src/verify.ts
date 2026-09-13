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
    const remote: unknown = await res.json();
    if (typeof remote !== 'object' || remote === null) {
      reasons.push('the registry answered with something this client could not read');
      return verdict;
    }
    const body = remote as { found?: unknown; recordFingerprint?: unknown; commitment?: unknown };
    verdict.known = body.found === true;

    // Registries carry the commitment under different names. Comparing against only
    // one meant a registry using the other reported "a different version" when the
    // record matched, which is an alarm a holder cannot act on.
    const theirs =
      typeof body.commitment === 'string'
        ? body.commitment
        : typeof body.recordFingerprint === 'string'
          ? body.recordFingerprint
          : undefined;

    if (theirs === undefined) {
      reasons.push('the registry did not return a commitment, so its copy could not be compared');
    } else {
      verdict.matchesRegistry = theirs === env.commitment;
      if (!verdict.matchesRegistry) {
        reasons.push('the registry holds a different version of this record');
      }
    }
  } catch {
    reasons.push('the registry could not be reached — the local integrity check still passed');
    return verdict;
  }

  // An empty chain is not a clean one. The registry verifies the ancestors it is
  // handed, so asking with none returns ok over nothing checked — and a caller who
  // omitted the inconvenient generation gets the same answer as one with no
  // ancestors at all. Reporting that as cleanDescent: true was a pass on a question
  // nobody asked.
  if (!opts.chain || opts.chain.length === 0) {
    reasons.push(
      'clean descent was not checked: no ancestors were supplied, and an empty chain ' +
        'establishes nothing about a record that has ancestors',
    );
  } else {
    try {
      const res = await fetch(`${base}/lineage/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ record: env.commitment, chain: opts.chain }),
      });
      const descent: unknown = await res.json();
      const ok = typeof descent === 'object' && descent !== null && (descent as { ok?: unknown }).ok === true;
      verdict.cleanDescent = ok;
      const reason = (descent as { reason?: unknown })?.reason;
      if (!ok) reasons.push(typeof reason === 'string' ? reason : 'clean descent was not established');
    } catch {
      reasons.push('clean-descent could not be checked');
    }
  }

  return verdict;
};
