// Batch anchoring.
//
// Anchoring every record individually would mean every holder needs a funded wallet —
// which is a barrier no lab technician will cross — and one transaction per record,
// which does not survive contact with volume.
//
// Instead, commitments are aggregated into a Merkle tree and only the root is anchored.
// One transaction covers thousands of records. This is the pattern OpenTimestamps has
// used to process over a billion timestamps, and Certificate Transparency before it.
//
// The property that matters most: a proof is self-contained. It carries the path from
// a record to a root, and a reference to where that root was anchored. Verifying it
// needs this package and a chain lookup — no registry, no account, and nothing that
// stops working if the registry does.
//
// SPDX-License-Identifier: Apache-2.0

import { sha256Hex } from './hash.js';

/** Domain separator, so a leaf can never be confused with an interior node. */
const LEAF = '00';
const NODE = '01';

const hashLeaf = (commitment: string): Promise<string> => sha256Hex(LEAF + commitment);
const hashNode = (left: string, right: string): Promise<string> => sha256Hex(NODE + left + right);

export type ProofStep = {
  /** The sibling hash at this level. */
  sibling: string;
  /** Whether the sibling sits on the left. */
  siblingIsLeft: boolean;
};

/** Where a batch root was anchored. Absent while the batch is still pending. */
export type AnchorRef = {
  chain: string;
  network: string;
  contractAddress?: string;
  txHash?: string;
  blockHeight?: number;
  anchoredAt?: string;
};

/**
 * A self-contained proof that a record was included in an anchored batch.
 *
 * Deliberately carries everything needed to verify it. A holder can keep this file and
 * prove their record's age years later, with no dependency on the registry that issued
 * it — which is the only basis on which a registry someone else runs could adopt this.
 */
export type InclusionProof = {
  formatVersion: string;
  /** The record commitment being proven. */
  commitment: string;
  /** Path from the leaf to the root, bottom-up. */
  path: ProofStep[];
  /** The batch root the path folds to. */
  root: string;
  /** Identifier of the batch, for looking it up. */
  batchId: string;
  /** When the batch was sealed, distinct from when it was anchored. */
  sealedAt: string;
  /** Where the root was anchored. Absent means pending. */
  anchor?: AnchorRef;
};

export type Batch = {
  batchId: string;
  root: string;
  sealedAt: string;
  /** One proof per included commitment, keyed by commitment. */
  proofs: Record<string, InclusionProof>;
};

/**
 * Build a batch from a set of record commitments.
 *
 * Commitments are sorted so the same set always produces the same root regardless of
 * insertion order — which means a batch can be rebuilt and checked independently.
 *
 * An odd node at any level is promoted rather than duplicated. Duplicating is the
 * classic Merkle malleability bug: it lets two different leaf sets produce the same
 * root.
 */
export const buildBatch = async (
  commitments: string[],
  batchId: string,
  sealedAt: string = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
): Promise<Batch> => {
  if (commitments.length === 0) throw new Error('cannot build an empty batch');

  const sorted = [...new Set(commitments)].sort();
  const leaves = await Promise.all(sorted.map(hashLeaf));

  // Each level, recording for every original leaf which sibling it was paired with.
  const paths: ProofStep[][] = sorted.map(() => []);
  let level = leaves;
  let indexOf = sorted.map((_, i) => i);

  while (level.length > 1) {
    const next: string[] = [];
    const nextIndex: number[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 >= level.length) {
        // Promoted, not duplicated.
        next.push(level[i]);
        nextIndex.push(i);
        continue;
      }
      next.push(await hashNode(level[i], level[i + 1]));
      nextIndex.push(i);
    }
    // Record this level's sibling for every leaf still being tracked.
    for (let leafIdx = 0; leafIdx < sorted.length; leafIdx++) {
      const pos = indexOf[leafIdx];
      const isRight = pos % 2 === 1;
      const siblingPos = isRight ? pos - 1 : pos + 1;
      if (siblingPos < level.length) {
        paths[leafIdx].push({ sibling: level[siblingPos], siblingIsLeft: isRight });
      }
      indexOf[leafIdx] = Math.floor(pos / 2);
    }
    level = next;
  }

  const root = level[0];
  const proofs: Record<string, InclusionProof> = {};
  sorted.forEach((commitment, i) => {
    proofs[commitment] = {
      formatVersion: '0.1',
      commitment,
      path: paths[i],
      root,
      batchId,
      sealedAt,
    };
  });

  return { batchId, root, sealedAt, proofs };
};

/**
 * Verify an inclusion proof.
 *
 * Offline and self-contained: this proves the commitment is in the batch whose root the
 * proof names. Whether that root was anchored, and when, is a separate lookup the
 * caller does against the chain — kept separate so a proof can be checked with no
 * network at all.
 */
export const verifyInclusion = async (proof: InclusionProof): Promise<boolean> => {
  let node = await hashLeaf(proof.commitment);
  for (const step of proof.path) {
    node = step.siblingIsLeft
      ? await hashNode(step.sibling, node)
      : await hashNode(node, step.sibling);
  }
  return node === proof.root;
};
