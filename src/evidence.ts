// Evidence packages: everything a lawyer, examiner or court needs to check a record, in
// one folder, with no dependency on VeilCore.
//
// The package carries the record, its inclusion proof, the batch root and its
// OpenTimestamps file where there is one, any claims, a plain-English guide, a template
// declaration for counsel to adapt, a standalone verifier (verify.py: the reference
// Python implementation, standard library only), and a manifest of every file's SHA-256.
//
// What it proves, and what it does not, is stated in the guide in the same words as SPEC
// section 9: the record is unaltered and was in a batch; when that batch was anchored is
// a lookup; whether the record is TRUE is not established by any of it.
//
// SPDX-License-Identifier: Apache-2.0

import { computeCommitment } from './commit.js';
import { verifyInclusion, type InclusionProof } from './batch.js';
import { toHex } from './hash.js';
import type { Envelope } from './types.js';
import { VERIFY_PY } from './evidence-verifier.generated.js';

export type EvidenceInput = {
  /** The record as the holder chooses to disclose it: all committed fields are needed to recompute it. */
  record: Envelope;
  /** The record's inclusion proof (SPEC 5.4), if it is in a batch. */
  proof?: InclusionProof;
  /** The batch root as 32 bytes, and its OpenTimestamps file, if there is one. */
  opentimestamps?: { rootBin: Uint8Array; ots: Uint8Array };
  /** Claims about the record from the claims contract, as the holder's tool recorded them. */
  claims?: unknown[];
  /** When the package was made (RFC 3339). Defaults to now. */
  generatedAt?: string;
};

export type EvidencePackage = Record<string, Uint8Array>;

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const json = (v: unknown): Uint8Array => utf8(JSON.stringify(v, null, 2) + '\n');

const sha256 = async (bytes: Uint8Array): Promise<string> => {
  const g = globalThis as { crypto?: { subtle?: SubtleCrypto } };
  if (g.crypto?.subtle) return toHex(new Uint8Array(await g.crypto.subtle.digest('SHA-256', bytes as BufferSource)));
  const nodeCrypto = await import(/* @vite-ignore */ 'node' + ':crypto');
  return nodeCrypto.createHash('sha256').update(bytes).digest('hex');
};

// A date from a test network, or from no anchor at all, is not evidence. Say so at the top.
const datingWarning = (input: EvidenceInput): string[] => {
  const proofAnchor = input.proof?.anchor;
  const recordAnchor = input.record.anchor;
  if (!proofAnchor && recordAnchor && (recordAnchor.kind ?? 'ledger') !== 'ledger') return [];
  const a = proofAnchor ?? recordAnchor;
  if (!a) return [];
  const bitcoin = input.opentimestamps ? ' The OpenTimestamps proof, once confirmed, is the only date here.' : '';
  if (a.network === 'undeployed') {
    return [`NOT ANCHORED ON A LEDGER: the record states no ledger anchor.${bitcoin}`, ''];
  }
  if (a.network !== 'mainnet') {
    return [
      `TEST NETWORK: the ledger anchor is on ${a.chain} ${a.network}, which can be reset.`,
      `A date from a test network carries no evidentiary weight.${bitcoin}`,
      '',
    ];
  }
  return [];
};

const guide = (input: EvidenceInput, commitment: string): string => {
  const p = input.proof;
  const lines = [
    'VEILCORE EVIDENCE PACKAGE',
    '',
    ...datingWarning(input),
    `Record:      ${input.record.recordId}`,
    `Commitment:  ${commitment}`,
    `Sealed at:   ${input.record.sealedAt} (the holder's statement; the anchor below is the independent date)`,
    `Prepared:    ${input.generatedAt ?? new Date().toISOString()}`,
    '',
    'WHAT IS IN THIS FOLDER',
    '  record.json            the record, with every field its commitment covers',
    ...(p ? ['  inclusion-proof.json   proof that the commitment is in a sealed batch'] : []),
    ...(input.opentimestamps ? ['  root.bin, root.bin.ots the batch root and its OpenTimestamps (Bitcoin) proof'] : []),
    ...(input.claims?.length ? ['  claims.json            facts about the record proved on the ledger (SPEC 4.5)'] : []),
    '  verify.py              a checker anyone can run: Python 3, nothing to install',
    '  DECLARATION-TEMPLATE.txt  a starting point for counsel; not a finished document',
    '  MANIFEST.json          the SHA-256 of every file above',
    '',
    'HOW TO CHECK IT',
    '  1. Run:  python3 verify.py',
    '     It confirms every file is unchanged, recomputes the commitment from record.json',
    '     (proving the record is exactly as sealed), and folds the inclusion proof to the',
    '     batch root. It needs no network and nothing from VeilCore.',
    '  2. Confirm the date. The batch root was published on a ledger at the time shown by the',
    '     transaction named in inclusion-proof.json; look it up in any explorer or indexer for',
    '     that network. Where root.bin.ots is present, confirm it against Bitcoin with the',
    '     OpenTimestamps client: `ots upgrade root.bin.ots` then `ots verify root.bin.ots`.',
    '     Either date stands on its own; neither depends on VeilCore still existing. A date',
    '     from a test network (preview, preprod, undeployed) is not evidence.',
    '  3. The same checks can be made with the TypeScript or Rust implementations, or written',
    '     from the specification (SPEC sections 4, 5 and 9), which is public.',
    '',
    'WHAT THIS ESTABLISHES',
    '  That this record existed, exactly as it reads, no later than the anchor\'s date.',
    '',
    'WHAT IT DOES NOT ESTABLISH (SPEC 9.3)',
    '  That the record is true. That any material is the subject it describes (that needs',
    '  inspection or genetic analysis). That anything still exists. It creates no right: it',
    '  supports claims made under rights that exist independently.',
  ];
  return lines.join('\n') + '\n';
};

const DECLARATION = `DECLARATION TEMPLATE - FOR COUNSEL TO ADAPT

This is a starting point, not legal advice and not a finished document. Requirements differ
by court and jurisdiction. In US federal courts, Federal Rule of Evidence 902(14) allows
data copied from an electronic file to be self-authenticated by the certification of a
qualified person that the copy was identified by its hash value; Rule 902(13) covers
records generated by an electronic process. Some states have their own rules (for example
Vermont, 12 V.S.A. section 1913). Elsewhere, ask local counsel.

I, [NAME], declare:

1. I am [ROLE] at [ORGANISATION] and am qualified to make this declaration because [BASIS:
   e.g. I administer the systems that created and stored the records described below].

2. The file record.json in the accompanying package is a record kept by [ORGANISATION] in
   the course of its regularly conducted activity, made at or near the time of the matters
   it describes. [Adapt to the facts.]

3. The SHA-256 commitment of that record, computed as described in the VeilCore
   specification (sections 4 and 5), is [COMMITMENT]. I computed it on [DATE] using
   [TOOL, e.g. the verify.py included in the package], and it matches the commitment
   stated in the record.

4. That commitment is included in a batch whose root is [ROOT], which was published
   [on LEDGER in transaction TX at block HEIGHT on DATE] [and stamped with OpenTimestamps,
   confirmed in Bitcoin block HEIGHT on DATE].

5. A copy that produces the same commitment is, with overwhelming probability, identical to
   the original: producing a different record with the same SHA-256 commitment is not
   computationally feasible. A copy that produces a different commitment is not identical.

I declare under penalty of perjury under the laws of [JURISDICTION] that the foregoing is
true and correct.

Executed on [DATE] at [PLACE].

[SIGNATURE]
`;

/** Build an evidence package: file name to bytes. Zip it, or write it to a folder. */
export const buildEvidencePackage = async (input: EvidenceInput): Promise<EvidencePackage> => {
  const commitment = await computeCommitment(input.record);
  if (commitment !== input.record.commitment) throw new Error('the record does not match its own commitment; it would fail every check');
  if (input.proof) {
    if (input.proof.commitment !== commitment) throw new Error('the inclusion proof is for a different record');
    if (!(await verifyInclusion(input.proof))) throw new Error('the inclusion proof does not fold to its root');
  }
  if (input.opentimestamps && input.proof && toHex(input.opentimestamps.rootBin) !== input.proof.root) {
    throw new Error('root.bin is not this record\'s batch root');
  }
  // The readable JSON is written, not the canonical form; verify.py recomputes from it.
  const files: EvidencePackage = {
    'record.json': json(input.record),
    'README.txt': utf8(guide(input, commitment)),
    'DECLARATION-TEMPLATE.txt': utf8(DECLARATION),
    'verify.py': utf8(VERIFY_PY),
  };
  if (input.proof) files['inclusion-proof.json'] = json(input.proof);
  if (input.opentimestamps) {
    files['root.bin'] = new Uint8Array(input.opentimestamps.rootBin);
    files['root.bin.ots'] = new Uint8Array(input.opentimestamps.ots);
  }
  if (input.claims?.length) files['claims.json'] = json(input.claims);
  const manifest: Record<string, string> = {};
  for (const name of Object.keys(files).sort()) manifest[name] = await sha256(files[name]);
  files['MANIFEST.json'] = json({ format: 'veilcore-evidence/v1', commitment, files: manifest });
  return files;
};

export type EvidenceCheck = { ok: boolean; checks: { ok: boolean; what: string }[] };

/** The offline checks verify.py makes, in TypeScript. */
export const verifyEvidencePackage = async (files: EvidencePackage): Promise<EvidenceCheck> => {
  const checks: { ok: boolean; what: string }[] = [];
  const add = (ok: boolean, what: string): void => {
    checks.push({ ok, what });
  };
  const read = (n: string): unknown => JSON.parse(new TextDecoder().decode(files[n]));
  if (!files['MANIFEST.json']) return { ok: false, checks: [{ ok: false, what: 'no MANIFEST.json' }] };
  const manifest = read('MANIFEST.json') as { files: Record<string, string> };
  for (const [name, digest] of Object.entries(manifest.files)) {
    add(files[name] !== undefined && (await sha256(files[name])) === digest, `${name} is unchanged`);
  }
  let commitment: string | undefined;
  try {
    const record = read('record.json') as Envelope;
    commitment = await computeCommitment(record);
    add(commitment === record.commitment, 'the record recomputes to its commitment');
  } catch (e) {
    add(false, `the record cannot be recomputed: ${(e as Error).message}`);
  }
  if (files['inclusion-proof.json']) {
    const proof = read('inclusion-proof.json') as InclusionProof;
    add(proof.commitment === commitment, 'the inclusion proof is for this record');
    add(await verifyInclusion(proof), 'the inclusion proof folds to its root');
    if (files['root.bin']) add(toHex(files['root.bin']) === proof.root, 'root.bin is the batch root');
  }
  return { ok: checks.every((c) => c.ok), checks };
};
