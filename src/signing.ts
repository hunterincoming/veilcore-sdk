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
import { attestationPayload, retractionPayload, type SignedAttestation, type Retraction } from './attester.js';
import { challengePayload, type Challenge } from './challenge.js';

const subtle = (): SubtleCrypto => {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error('WebCrypto unavailable');
  return c.subtle;
};

// Cast at the WebCrypto boundary: the DOM types want BufferSource and a Uint8Array
// over a generic ArrayBufferLike does not satisfy it, though it is one at runtime.
const fromHex = (hex: string): BufferSource =>
  new Uint8Array((hex.match(/.{1,2}/g) ?? []).map((b) => parseInt(b, 16))) as unknown as BufferSource;

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

const importPrivate = (hex: string): Promise<CryptoKey> =>
  subtle().importKey('pkcs8', fromHex(hex), { name: 'Ed25519' }, false, ['sign']);

const importPublic = (hex: string): Promise<CryptoKey> =>
  subtle().importKey('raw', fromHex(hex), { name: 'Ed25519' }, false, ['verify']);

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
  if (!a.signature) return false;
  try {
    const key = await importPublic(a.attester.publicKey);
    const { signature, signatureAlgorithm, ...unsigned } = a;
    return await subtle().verify('Ed25519', key, fromHex(signature), bytes(attestationPayload(unsigned)));
  } catch {
    return false;
  }
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
  if (!r.signature) return false;
  if (r.attestationId !== a.attestationId) return false;
  if (r.attesterPublicKey !== a.attester.publicKey) return false;
  try {
    const key = await importPublic(r.attesterPublicKey);
    const { signature, ...unsigned } = r;
    return await subtle().verify('Ed25519', key, fromHex(signature), bytes(retractionPayload(unsigned)));
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
  if (!c.signature) return false;
  if (!c.claimCommitment) return false; // a challenge with nothing sealed behind it
  try {
    const key = await importPublic(c.challenger.publicKey);
    const { signature, signatureAlgorithm, response, resolution, state, ...unsigned } = c;
    return await subtle().verify('Ed25519', key, fromHex(signature), bytes(challengePayload(unsigned as never)));
  } catch {
    return false;
  }
};
