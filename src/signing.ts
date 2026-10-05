// Signing and verifying attestations.
//
// The signature is what makes an attestation belong to someone. Without it, an
// attestation is a claim the registry makes about a party rather than a statement the
// party made — and a registry that can write attestations on behalf of labs is a
// registry that can forge evidence.
//
// Ed25519 via WebCrypto, so this works in a browser and in Node with no dependencies.
// A lab generates a keypair once, keeps the private key, and publishes the public one.
//
// SPDX-License-Identifier: Apache-2.0

import { toHex } from './hash.js';
import { attestationPayload, retractionPayload, strengthOf, type AttestationStrength, type SignedAttestation, type Retraction } from './attester.js';
import { challengePayload, type Challenge } from './challenge.js';

const subtle = (): SubtleCrypto => {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error('WebCrypto unavailable');
  return c.subtle;
};

// Strict hex: lowercase, exactly the stated number of bytes. The old reader took pairs of
// characters through parseInt, so "0g", "0G" and "00" all read as the byte 0 and an odd
// length kept a dangling nibble: one signature had many spellings that verified, and an
// uppercase key verified while attesterId() (a hash of the key TEXT) named a different
// attester. Cast at the WebCrypto boundary: the DOM types want BufferSource.
const strictHex = (hex: unknown, bytes: number, what: string): Uint8Array => {
  if (typeof hex !== 'string' || hex.length !== bytes * 2 || !/^[0-9a-f]*$/.test(hex)) {
    throw new Error(`${what} is ${bytes * 2} lowercase hex characters`);
  }
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
};
const buf = (b: Uint8Array): BufferSource => b as unknown as BufferSource;

// Ed25519 public keys that no one holds a private key for. With a small-order key (the
// identity, for one), the signature R = that point, S = 0 verifies for EVERY message under
// the cofactorless check WebCrypto runs: checked on Node 22, the attestation then reports
// "signed" over anything at all. The list is the small-order points (libsodium's
// ge25519_has_small_order), compared with the x-sign bit cleared, plus any y >= p.
const SMALL_ORDER = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
];
const checkPublicKey = (key: Uint8Array): void => {
  const y = new Uint8Array(key);
  y[31] &= 0x7f;
  const yHex = Array.from(y, (b) => b.toString(16).padStart(2, '0')).join('');
  if (SMALL_ORDER.includes(yHex)) throw new Error('a small-order Ed25519 key cannot sign anything');
  // y >= p = 2^255 - 19: not a canonical encoding.
  if (y[31] === 0x7f && y.subarray(1, 31).every((b) => b === 0xff) && y[0] >= 0xed) {
    throw new Error('the public key is not a canonical Ed25519 encoding');
  }
};

const bytes = (s: string): BufferSource =>
  new TextEncoder().encode(s) as unknown as BufferSource;

export type Keypair = { publicKey: string; privateKey: string };

/**
 * Generate an attester keypair.
 *
 * The private key never leaves the attester. If they lose it they can no longer sign
 * new attestations — but past ones remain valid and retractable through the registry,
 * which is why retraction is a registry entry rather than a key operation.
 */
export const generateKeypair = async (): Promise<Keypair> => {
  const kp = await subtle().generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = await subtle().exportKey('raw', (kp as CryptoKeyPair).publicKey);
  const priv = await subtle().exportKey('pkcs8', (kp as CryptoKeyPair).privateKey);
  return { publicKey: toHex(new Uint8Array(pub)), privateKey: toHex(new Uint8Array(priv)) };
};

const importPrivate = (hex: string): Promise<CryptoKey> => {
  // PKCS#8, hex. Its length varies with the encoder (48 bytes from generateKeypair, more
  // when the public key is included), so only the spelling and an upper bound are fixed.
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || hex.length > 512 || !/^[0-9a-f]+$/.test(hex)) {
    return Promise.reject(new Error('the private key is PKCS#8 as lowercase hex'));
  }
  return subtle().importKey('pkcs8', buf(strictHex(hex, hex.length / 2, 'the private key')), { name: 'Ed25519' }, false, ['sign']);
};

const importPublic = (hex: unknown): Promise<CryptoKey> => {
  const key = strictHex(hex, 32, 'the public key');
  checkPublicKey(key);
  return subtle().importKey('raw', buf(key), { name: 'Ed25519' }, false, ['verify']);
};

/** An Ed25519 signature is 64 bytes. Absent or anything else does not verify. */
const signatureBytes = (sig: unknown): BufferSource => buf(strictHex(sig, 64, 'the signature'));

const isObject = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const isHex64 = (x: unknown): boolean => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
const isText = (x: unknown): boolean => typeof x === 'string' && x.length > 0;

/**
 * The signed fields SPEC 7 lists are present. Without subjectCommitment a signature is
 * "a portable credential that verifies anywhere it is pasted" (SPEC 7), and the payload
 * builder omits an absent field rather than refusing, so this is where it is required.
 */
const hasSignedFields = (a: Record<string, unknown>): boolean =>
  isText(a.attestationId) && isText(a.type) && isHex64(a.subjectCommitment) && isText(a.documentHash) &&
  a.hashAlgorithm === 'sha256' && isText(a.issuedAt);

/** `signatureAlgorithm` is optional, and when present it says ed25519. */
const ed25519Named = (alg: unknown): boolean => alg === undefined || alg === 'ed25519';

/** Sign an attestation. The payload is canonical, so any implementation reproduces it. */
export const signAttestation = async (
  a: Omit<SignedAttestation, 'signature' | 'signatureAlgorithm'>,
  privateKeyHex: string,
): Promise<SignedAttestation> => {
  const key = await importPrivate(privateKeyHex);
  const sig = await subtle().sign('Ed25519', key, bytes(attestationPayload(a)));
  return { ...a, signature: toHex(new Uint8Array(sig)), signatureAlgorithm: 'ed25519' };
};

/**
 * Verify an attestation's signature.
 *
 * Proves the attestation was made by the holder of that key. It does not prove the key
 * belongs to a real laboratory — that is what a trust registry is for, and no amount of
 * cryptography substitutes for it.
 */
export const verifyAttestation = async (a: SignedAttestation): Promise<boolean> => {
  // A verifier: anything malformed (null, a missing attester, a signature that is not 128
  // lowercase hex, an algorithm other than ed25519) is false, never an exception.
  try {
    if (!isObject(a) || !a.signature || !ed25519Named(a.signatureAlgorithm) || !isObject(a.attester)) return false;
    if (!hasSignedFields(a)) return false;
    const key = await importPublic(a.attester.publicKey);
    const { signature, signatureAlgorithm, ...unsigned } = a;
    return await subtle().verify('Ed25519', key, signatureBytes(signature), bytes(attestationPayload(unsigned)));
  } catch {
    return false;
  }
};

/**
 * SPEC 7.2 strength with the signature checked: `signed` (or `signed-and-accredited`)
 * only when it verifies, `invalid-signature` when a signature is present and does not.
 * `accreditation` remains the attester's own claim; a registry lookup is still needed
 * before reading it as an accreditor's (SPEC 7.3).
 */
export const verifiedStrengthOf = async (a: SignedAttestation): Promise<AttestationStrength | 'invalid-signature'> => {
  const claimed = strengthOf(a);
  if (claimed === 'unsigned') return 'unsigned';
  return (await verifyAttestation(a)) ? claimed : 'invalid-signature';
};

/** Sign a retraction. Only the issuing key can retract. */
export const signRetraction = async (
  r: Omit<Retraction, 'signature'>,
  privateKeyHex: string,
): Promise<Retraction> => {
  const key = await importPrivate(privateKeyHex);
  const sig = await subtle().sign('Ed25519', key, bytes(retractionPayload(r)));
  return { ...r, signature: toHex(new Uint8Array(sig)) };
};

/**
 * Verify a retraction against the attestation it retracts.
 *
 * Checks the signature AND that the retracting key is the one that issued the
 * attestation — so a third party cannot retract someone else's work, and a holder
 * cannot retract an attestation they did not make.
 */
export const verifyRetraction = async (r: Retraction, a: SignedAttestation): Promise<boolean> => {
  try {
    if (!isObject(r) || !isObject(a) || !isObject(a.attester)) return false;
    if (!r.signature) return false;
    if (r.attestationId !== a.attestationId) return false;
    if (r.attesterPublicKey !== a.attester.publicKey) return false;
    const key = await importPublic(r.attesterPublicKey);
    const { signature, ...unsigned } = r;
    return await subtle().verify('Ed25519', key, signatureBytes(signature), bytes(retractionPayload(unsigned)));
  } catch {
    return false;
  }
};

/**
 * Sign a challenge.
 *
 * An anonymous challenge is free to make and impossible to answer, which is the
 * definition of a griefing tool. The signature is what puts a name behind the assertion.
 */
export const signChallenge = async (
  c: Omit<Challenge, 'signature' | 'signatureAlgorithm'>,
  privateKeyHex: string,
): Promise<Challenge> => {
  const key = await importPrivate(privateKeyHex);
  const sig = await subtle().sign('Ed25519', key, bytes(challengePayload(c)));
  return { ...c, signature: toHex(new Uint8Array(sig)), signatureAlgorithm: 'ed25519' };
};

/**
 * Verify a challenge.
 *
 * Proves the challenger made this assertion. It says nothing about whether the
 * assertion is correct - that is for the parties and, if it comes to it, a court.
 */
export const verifyChallenge = async (c: Challenge): Promise<boolean> => {
  try {
    if (!isObject(c) || !c.signature || !ed25519Named(c.signatureAlgorithm) || !isObject(c.challenger)) return false;
    // A challenge names the record it contests and the challenger's own sealed claim, both
    // as commitments; one with nothing sealed behind it is an assertion with nothing behind it.
    if (!isHex64(c.claimCommitment) || !isHex64(c.subjectCommitment)) return false;
    const key = await importPublic(c.challenger.publicKey);
    const { signature, signatureAlgorithm, response, resolution, state, ...unsigned } = c;
    return await subtle().verify('Ed25519', key, signatureBytes(signature), bytes(challengePayload(unsigned as never)));
  } catch {
    return false;
  }
};
