// A record that names its own key, without showing it (SPEC 3.6.1).
//
// The record's key (its ledger identity, commit(record secret)) is made before the record
// is sealed. The committed fields carry keyBinding = H(keybind, identity, keySalt), and the
// fingerprint is built around it:
//
//   identity    = H("veilcore:v1:commit",    recordSecret)
//   keySalt     = H("veilcore:v1:keysalt",   recordSecret)
//   keyBinding  = H("veilcore:v1:keybind",   identity, keySalt)
//   contentHash = SHA-256 of the canonical serialisation (SPEC 4.4) of the committed fields,
//                 keyBinding included
//   fingerprint = H("veilcore:v1:keyrecord", keyBinding, contentHash)
//
// H as in SPEC 3.7 and 4.5 (SHA-256 over 32-byte elements, the tag right-padded with zero
// bytes). Committed fields with no keyBinding keep `sha256/canonical-json/v1`: their
// fingerprint is contentHash itself, byte for byte as before.
//
// A verifier given the fingerprint, an identity, keySalt and contentHash recomputes the
// fingerprint; if it matches, the identity is the key the record named when it was sealed.
// keyBinding says nothing about the identity without keySalt, which the holder keeps and
// never puts in the record. Vectors: conformance/vectors.json, sections keyBound*.
//
// SPDX-License-Identifier: Apache-2.0

import { canonicalise } from './canonical.js';
import { hashElements } from './fields.js';
import { sha256Hex, toHex } from './hash.js';
import type { VerifyResult } from './commit.js';

/** The algorithm identifier of a key-bound fingerprint (SPEC 3.6.1). */
export const KEY_BOUND_ALGORITHM = 'sha256/key-bound/v1';

/** The tags of SPEC 3.6.1. `veilcore:v1:commit` is the ledger contract's own commit(). */
export const KEY_BINDING_TAGS = {
  commit: 'veilcore:v1:commit',
  keySalt: 'veilcore:v1:keysalt',
  keyBinding: 'veilcore:v1:keybind',
  keyRecord: 'veilcore:v1:keyrecord',
} as const;

/** The algorithm of a fingerprint over committed fields with no keyBinding (unchanged). */
const OLDER_ALGORITHM = 'sha256/canonical-json/v1';

const HEX64 = /^[0-9a-f]{64}$/;
const isHex64 = (v: unknown): v is string => typeof v === 'string' && HEX64.test(v);

const bytes32 = (h: unknown, what: string): Uint8Array => {
  if (!isHex64(h)) throw new Error(`${what} must be 64 lowercase hex characters`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
};

const tagBytes = (t: string): Uint8Array => {
  const b = new Uint8Array(32);
  b.set(new TextEncoder().encode(t));
  return b;
};

const H = async (tag: string, ...parts: Uint8Array[]): Promise<string> =>
  toHex(await hashElements(tagBytes(tag), ...parts));

/** The record's ledger identity, commit(recordSecret): the contract's own, as plain SHA-256. */
export const identityFromSecret = async (recordSecret: string): Promise<string> =>
  H(KEY_BINDING_TAGS.commit, bytes32(recordSecret, 'recordSecret'));

/** The key's salt, from the record secret so a backup of the secret restores it. Never on the record. */
export const keySaltOf = async (recordSecret: string): Promise<string> =>
  H(KEY_BINDING_TAGS.keySalt, bytes32(recordSecret, 'recordSecret'));

/** The committed field: says nothing about the identity without its salt. */
export const keyBindingOf = async (identity: string, keySalt: string): Promise<string> =>
  H(KEY_BINDING_TAGS.keyBinding, bytes32(identity, 'identity'), bytes32(keySalt, 'keySalt'));

/** A key-bound fingerprint, from keyBinding and the content hash of the committed fields. */
export const keyBoundFingerprint = async (keyBinding: string, contentHash: string): Promise<string> =>
  H(KEY_BINDING_TAGS.keyRecord, bytes32(keyBinding, 'keyBinding'), bytes32(contentHash, 'contentHash'));

/** Everything a record needs to name its key, from its secret. */
export const bindingForSecret = async (
  recordSecret: string,
): Promise<{ identity: string; keySalt: string; keyBinding: string }> => {
  const identity = await identityFromSecret(recordSecret);
  const keySalt = await keySaltOf(recordSecret);
  return { identity, keySalt, keyBinding: await keyBindingOf(identity, keySalt) };
};

export type RecordFingerprint = {
  /** `sha256/key-bound/v1` when the fields carry keyBinding, else `sha256/canonical-json/v1`. */
  algorithm: typeof KEY_BOUND_ALGORITHM | typeof OLDER_ALGORITHM;
  /** SHA-256 of the canonical serialisation of the fields (a link's `cd`). */
  contentHash: string;
  /** The fingerprint: contentHash itself, or H(keyrecord, keyBinding, contentHash). */
  fingerprint: string;
};

/**
 * The fingerprint of committed JSON anchored on its own (SPEC 3.6.1 "Where it applies"),
 * such as the `fields` of an export's `org.veilcore.registered-fingerprint` extension.
 * The fields are hashed as given. A keyBinding that is present is sealed, and must be 64
 * lowercase hex characters (null, a number, upper case, 0x... are refused, not hashed).
 * Fields without keyBinding give contentHash, exactly as before.
 */
export const computeRecordFingerprint = async (fields: unknown): Promise<RecordFingerprint> => {
  if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) throw new Error('the committed fields are a JSON object');
  const kb = (fields as Record<string, unknown>).keyBinding;
  if (kb !== undefined && !isHex64(kb)) throw new Error('keyBinding must be 64 lowercase hex characters');
  const contentHash = await sha256Hex(canonicalise(fields));
  return kb === undefined
    ? { algorithm: OLDER_ALGORITHM, contentHash, fingerprint: contentHash }
    : { algorithm: KEY_BOUND_ALGORITHM, contentHash, fingerprint: await keyBoundFingerprint(kb, contentHash) };
};

/**
 * Check a registered fingerprint against the fields it claims to cover, as an export's
 * `org.veilcore.registered-fingerprint` extension carries them. When `algorithm` is given
 * it must be the one the fields call for. Never throws: malformed input is a failed check
 * with a reason. This says the fields are the ones fingerprinted; whether a given key is
 * the one they name is keyMatchesRecord.
 */
export const verifyRecordFingerprint = async (registered: {
  fields: unknown;
  fingerprint: unknown;
  algorithm?: unknown;
}): Promise<VerifyResult> => {
  try {
    if (typeof registered !== 'object' || registered === null) return { valid: false, reason: 'nothing to verify' };
    const { fields, fingerprint, algorithm } = registered;
    if (!isHex64(fingerprint)) return { valid: false, reason: 'the fingerprint is not 64 lowercase hex characters' };
    const r = await computeRecordFingerprint(fields);
    if (algorithm !== undefined && algorithm !== r.algorithm) {
      return {
        valid: false,
        computed: r.fingerprint,
        claimed: fingerprint,
        reason: `the fields call for ${r.algorithm}, not ${String(algorithm).slice(0, 80)}`,
      };
    }
    return r.fingerprint === fingerprint
      ? { valid: true, computed: r.fingerprint }
      : { valid: false, computed: r.fingerprint, claimed: fingerprint, reason: 'the fingerprint does not match the fields' };
  } catch (e) {
    return { valid: false, reason: (e as Error)?.message ?? String(e) };
  }
};

/** What a holder's link carries so a verifier can match a key to a record: fp, ks, cd. */
export type KeyedRecord = {
  /** The record's fingerprint, from a source the verifier trusts for that record. */
  fingerprint: string;
  /** The key's salt. */
  keySalt: string;
  /** SHA-256 of the record's committed fields. Reveals nothing: they include the nonce. */
  contentHash: string;
};

/**
 * Is this identity the key the record named when it was sealed (SPEC 3.6.1 "What a
 * verifier checks")? Recomputes H(keyrecord, H(keybind, identity, keySalt), contentHash)
 * and compares it with the fingerprint. Exact: every input is 64 lowercase hex characters,
 * and anything else does not match (it never throws). An older record, with no keyBinding,
 * matches no key: for it the link between identity and record is the holder's statement.
 */
export const keyMatchesRecord = async (identity: string, record: KeyedRecord): Promise<boolean> => {
  if (typeof record !== 'object' || record === null) return false;
  const { fingerprint, keySalt, contentHash } = record;
  if (![identity, fingerprint, keySalt, contentHash].every(isHex64)) return false;
  return (await keyBoundFingerprint(await keyBindingOf(identity, keySalt), contentHash)) === fingerprint;
};
