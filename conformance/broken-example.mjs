// A deliberately non-conformant implementation.
//
// Exists to prove the conformance suite detects failure. A suite that only ever passes
// is a suite that proves nothing — this is the control.
//
// The bug is subtle on purpose: plain JSON.stringify without sorted keys. It produces
// correct-looking output for records whose fields happen to be in the right order, and
// silently wrong commitments for everything else. Exactly the failure mode
// canonicalisation exists to prevent.
//
// It speaks the same stdin/stdout protocol as any other implementation, so you can point
// the runner at it and watch the suite fail:
//
//     node conformance/run-cli.mjs "node conformance/broken-example.mjs"
//
// Until August 2026 it exported functions instead, which meant the one thing it existed
// to demonstrate could not actually be demonstrated. Found by external review.
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


// ---------------------------------------------------------------------------
// The runner protocol: read a job on stdin, write a result on stdout.

const input = await new Promise((resolve) => {
  let buf = '';
  process.stdin.on('data', (d) => { buf += d; });
  process.stdin.on('end', () => resolve(buf));
});

const job = JSON.parse(input);
let result;

if (job.op === 'canonicalise') {
  result = { result: canonicalise(job.input) };
} else if (job.op === 'commit') {
  result = { result: await computeCommitment(job.input) };
} else {
  result = { error: `unknown op ${job.op}` };
}

console.log(JSON.stringify(result));
