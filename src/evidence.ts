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
import type { Anchor, Envelope } from './types.js';
import { anchorsOf } from './anchors.js';
import { timestampTokenBytes, verifyTimestampToken } from './rfc3161.js';
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

const HEX64 = /^[0-9a-f]{64}$/;
/** 32 bytes from 64 lowercase hex characters; anything else throws. */
const fromHex = (h: unknown): Uint8Array => {
  if (typeof h !== 'string' || !HEX64.test(h)) throw new Error('expected 64 lowercase hex characters');
  return Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
};

/** The OpenTimestamps file header (magic and version 1), then op sha256 (0x08) and its digest. */
const OTS_MAGIC = Uint8Array.from([
  0x00, ...Array.from('OpenTimestamps', (c) => c.charCodeAt(0)), 0x00, 0x00, ...Array.from('Proof', (c) => c.charCodeAt(0)), 0x00,
  0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
const eqBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/** Names a manifest may list: one plain file name, as the builder writes them. No paths. */
const PLAIN_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;

/**
 * The RFC 3161 tokens a package carries, and what each stamps. The naming is fixed so
 * verify.py finds the same files: a record's rfc3161 anchors that carry a token, in order,
 * are rfc3161-record-1.tst, -2, ...; one on the inclusion proof is rfc3161-batch.tst.
 * Record tokens stamp commitment.bin (the commitment's 32 raw bytes); a batch token stamps
 * root.bin (the batch root's 32 raw bytes). SPEC 3.2.
 */
const timestampsOf = (record: Envelope, proof?: InclusionProof): { file: string; anchor: Anchor; data: 'commitment.bin' | 'root.bin' }[] => {
  const out: { file: string; anchor: Anchor; data: 'commitment.bin' | 'root.bin' }[] = [];
  anchorsOf(record)
    .filter((a) => a.kind === 'rfc3161' && a.token)
    .forEach((anchor, i) => out.push({ file: `rfc3161-record-${i + 1}.tst`, anchor, data: 'commitment.bin' }));
  const pa = proof?.anchor;
  if (pa && pa.kind === 'rfc3161' && pa.token) out.push({ file: 'rfc3161-batch.tst', anchor: pa as Anchor, data: 'root.bin' });
  return out;
};

// A date from a test network, or from no anchor at all, is not evidence. Say so at the top.
const datingWarning = (input: EvidenceInput): string[] => {
  const proofAnchor = input.proof?.anchor;
  const recordAnchor = input.record.anchor;
  if (!proofAnchor && recordAnchor && (recordAnchor.kind ?? 'ledger') !== 'ledger') return [];
  const a = proofAnchor ?? recordAnchor;
  if (!a || Array.isArray(a)) return [];
  if ((a.kind ?? 'ledger') !== 'ledger') return [];
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
    ...(timestampsOf(input.record, p).length
      ? ['  rfc3161-*.tst          RFC 3161 timestamp tokens, with the bytes they stamp (commitment.bin, root.bin)']
      : []),
    ...(input.claims?.length ? ['  claims.json            facts about the record proved on the ledger (SPEC 4.5)'] : []),
    '  verify.py              a checker anyone can run: Python 3, nothing to install',
    '  DECLARATION-TEMPLATE.txt  a starting point for counsel; not a finished document',
    '  MANIFEST.json          the SHA-256 of every file above. It catches accidental damage',
    '                         (a truncated copy, a re-saved file). It does NOT catch deliberate',
    '                         editing: it sits beside the files, so whoever edits one can',
    '                         rewrite it too. What deliberate editing cannot get past is the',
    '                         commitment recomputed from record.json and its anchor (step 2).',
    '',
    'HOW TO CHECK IT',
    '  1. Run:  python3 verify.py',
    '     It confirms every file matches MANIFEST.json, recomputes the commitment from record.json',
    '     (proving the record is exactly as sealed), and folds the inclusion proof to the',
    '     batch root. It needs no network and nothing from VeilCore.',
    '  2. Confirm the date. The batch root was published on a ledger at the time shown by the',
    '     transaction named in inclusion-proof.json; look it up in any explorer or indexer for',
    '     that network. Where root.bin.ots is present, confirm it against Bitcoin with the',
    '     OpenTimestamps client: `ots upgrade root.bin.ots` then `ots verify root.bin.ots`.',
    '     Either date stands on its own; neither depends on VeilCore still existing. A date',
    '     from a test network (preview, preprod, undeployed) is not evidence.',
    ...(timestampsOf(input.record, p).length
      ? [
          '     Where an rfc3161-*.tst token is present, verify.py prints the `openssl ts -verify`',
          '     command that checks it; you supply the TSA\'s root certificate. Where the TSA claims',
          '     qualified status, confirm that on the EU trusted list, which openssl does not consult.',
        ]
      : []),
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
  if (input.opentimestamps) {
    // An OpenTimestamps file dates a batch root. Without the inclusion proof that ties the
    // root to this record it dates nothing a reader of the package can connect to it.
    if (!input.proof) throw new Error('an OpenTimestamps file needs the inclusion proof that ties its root to the record');
    const { rootBin, ots } = input.opentimestamps;
    if (!(rootBin instanceof Uint8Array) || rootBin.length !== 32) throw new Error('root.bin is the batch root\'s 32 raw bytes');
    if (!(ots instanceof Uint8Array)) throw new Error('the OpenTimestamps file is bytes');
    if (toHex(rootBin) !== input.proof.root) throw new Error('root.bin is not this record\'s batch root');
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
  for (const t of timestampsOf(input.record, input.proof)) {
    const der = timestampTokenBytes(t.anchor.token!);
    if (!der) throw new Error(`the RFC 3161 token for ${t.file} does not parse`);
    files[t.file] = der;
    if (t.data === 'commitment.bin') files['commitment.bin'] = fromHex(commitment);
    else files['root.bin'] = fromHex(input.proof!.root);
  }
  if (input.claims?.length) files['claims.json'] = json(input.claims);
  const manifest: Record<string, string> = {};
  for (const name of Object.keys(files).sort()) manifest[name] = await sha256(files[name]);
  files['MANIFEST.json'] = json({ format: 'veilcore-evidence/v1', commitment, files: manifest });
  return files;
};

export type EvidenceCheck = {
  ok: boolean;
  checks: { ok: boolean; what: string }[];
  /** What a passing package still leaves unchecked (for example, a timestamp's chain of trust). */
  notChecked?: string[];
};

/**
 * The offline checks verify.py makes, in TypeScript. Never throws: a malformed package is
 * a failed check with a reason.
 *
 * MANIFEST.json is checked, and it only catches accidental damage: it travels with the
 * files, so anyone who edits a file can rewrite it. A package is trustworthy because its
 * record recomputes to its commitment and that commitment is anchored, not because of the
 * manifest.
 */
export const verifyEvidencePackage = async (files: EvidencePackage): Promise<EvidenceCheck> => {
  const checks: { ok: boolean; what: string }[] = [];
  const notChecked = new Set<string>();
  try {
    await checkPackage(files, checks, notChecked);
  } catch (e) {
    checks.push({ ok: false, what: `the package could not be checked: ${(e as Error)?.message ?? String(e)}` });
  }
  return { ok: checks.length > 0 && checks.every((c) => c.ok), checks, ...(notChecked.size ? { notChecked: [...notChecked] } : {}) };
};

const checkPackage = async (files: EvidencePackage, checks: { ok: boolean; what: string }[], notChecked: Set<string>): Promise<void> => {
  const add = (ok: boolean, what: string): boolean => {
    checks.push({ ok, what });
    return ok;
  };
  if (typeof files !== 'object' || files === null) {
    add(false, 'the package is not a set of files');
    return;
  }
  const has = (n: string): boolean => Object.hasOwn(files, n) && files[n] instanceof Uint8Array;
  // JSON files are read strictly: UTF-8 that does not decode, or text that does not parse,
  // is a failed check rather than an exception.
  const readJson = (n: string): { ok: true; value: unknown } | { ok: false; why: string } => {
    if (!has(n)) return { ok: false, why: `${n} is missing` };
    try {
      return { ok: true, value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(files[n])) };
    } catch (e) {
      return { ok: false, why: `${n} is not valid JSON: ${(e as Error).message}` };
    }
  };
  const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

  // 1. The manifest: the right shape, plain names, and every file in the package listed.
  const m = readJson('MANIFEST.json');
  if (!m.ok) {
    add(false, m.ok === false ? m.why : 'no MANIFEST.json');
    return;
  }
  const manifest = m.value;
  if (!isObj(manifest) || !isObj(manifest.files) || manifest.format !== 'veilcore-evidence/v1') {
    add(false, 'MANIFEST.json is not a veilcore-evidence/v1 manifest');
    return;
  }
  const listed = Object.entries(manifest.files);
  for (const [name, digest] of listed) {
    if (!PLAIN_NAME.test(name) || name === 'MANIFEST.json') {
      add(false, `MANIFEST.json lists ${JSON.stringify(name.slice(0, 100))}, which is not a plain file name`);
      continue;
    }
    if (typeof digest !== 'string' || !HEX64.test(digest)) {
      add(false, `MANIFEST.json gives no SHA-256 for ${name}`);
      continue;
    }
    add(has(name) && (await sha256(files[name])) === digest, `${name} is unchanged`);
  }
  for (const name of Object.keys(files)) {
    if (name !== 'MANIFEST.json' && !Object.hasOwn(manifest.files, name)) {
      add(false, `${name.slice(0, 100)} is not in MANIFEST.json: it was added after the package was built`);
    }
  }
  for (const required of ['record.json', 'verify.py']) {
    if (!Object.hasOwn(manifest.files, required)) add(false, `MANIFEST.json does not list ${required}`);
  }

  // 2. The record recomputes to its commitment.
  let commitment: string | undefined;
  let record: Envelope | undefined;
  const r = readJson('record.json');
  if (!r.ok) {
    add(false, `the record cannot be recomputed: ${r.ok === false ? r.why : ''}`);
  } else if (!isObj(r.value)) {
    add(false, 'the record cannot be recomputed: record.json is not an object');
  } else {
    record = r.value as Envelope;
    try {
      commitment = await computeCommitment(record);
      add(commitment === record.commitment, 'the record recomputes to its commitment');
    } catch (e) {
      commitment = undefined;
      add(false, `the record cannot be recomputed: ${(e as Error).message}`);
    }
  }
  if (manifest.commitment !== undefined && commitment !== undefined) {
    add(manifest.commitment === commitment, 'MANIFEST.json names this record\'s commitment');
  }
  if (has('commitment.bin') && commitment !== undefined) {
    add(eqBytes(files['commitment.bin'], fromHex(commitment)), 'commitment.bin is the record\'s commitment');
  }

  // 3. The inclusion proof folds, and root.bin is its root.
  let proof: InclusionProof | undefined;
  if (Object.hasOwn(files, 'inclusion-proof.json')) {
    const p = readJson('inclusion-proof.json');
    if (!p.ok || !isObj(p.value)) {
      add(false, p.ok ? 'inclusion-proof.json is not an object' : p.why);
    } else {
      proof = p.value as InclusionProof;
      add(commitment !== undefined && proof.commitment === commitment, 'the inclusion proof is for this record');
      add(await verifyInclusion(proof), 'the inclusion proof folds to its root');
    }
  }
  if (has('root.bin')) {
    add(proof !== undefined && typeof proof.root === 'string' && HEX64.test(proof.root) && toHex(files['root.bin']) === proof.root,
      'root.bin is the batch root of this record\'s inclusion proof');
  }

  // 4. The OpenTimestamps file names root.bin (the same check verify.py makes). Whether
  // Bitcoin confirms it is a lookup: `ots verify`.
  if (Object.hasOwn(files, 'root.bin.ots')) {
    const ots = files['root.bin.ots'];
    const ok = has('root.bin.ots') && has('root.bin') && ots.length >= OTS_MAGIC.length + 34 &&
      eqBytes(ots.subarray(0, OTS_MAGIC.length), OTS_MAGIC) && ots[OTS_MAGIC.length] === 0x01 && ots[OTS_MAGIC.length + 1] === 0x08 &&
      eqBytes(ots.subarray(OTS_MAGIC.length + 2, OTS_MAGIC.length + 34), await sha256Bytes(files['root.bin']));
    add(ok, 'root.bin.ots is an OpenTimestamps (version 1) proof whose first operation hashes root.bin');
    if (ok) notChecked.add('root.bin.ots: the Bitcoin attestation (ots upgrade, then ots verify)');
  }

  // 5. RFC 3161 tokens: checked offline against the bytes they stamp. A saved .tst file is
  // the token the record or proof states, byte for byte.
  if (record !== undefined) {
    for (const t of timestampsOf(record, proof)) {
      const stamped = t.data === 'commitment.bin' ? record.commitment : proof?.root;
      if (typeof stamped !== 'string' || !HEX64.test(stamped)) {
        add(false, `${t.file}: there are no stamped bytes to compare it with`);
        continue;
      }
      if (Object.hasOwn(files, t.file)) {
        const der = typeof t.anchor.token === 'string' ? timestampTokenBytes(t.anchor.token) : undefined;
        add(has(t.file) && der !== undefined && eqBytes(files[t.file], der), `${t.file} is the token the ${t.data === 'commitment.bin' ? 'record' : 'inclusion proof'} states`);
      }
      const v = await verifyTimestampToken(t.anchor.token!, fromHex(stamped));
      for (const c of v.checks) add(c.ok, `${t.file}: ${c.what}`);
      if (v.ok) add(true, `${t.file}: the TSA states ${v.genTime}, signed by "${v.signerSubject}"`);
      v.notChecked.forEach((x) => notChecked.add(`${t.file}: ${x}`));
    }
  }
};

const sha256Bytes = async (bytes: Uint8Array): Promise<Uint8Array> => {
  const hex = await sha256(bytes);
  return fromHex(hex);
};
