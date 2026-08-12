// Attester identity.
//
// An attestation is only worth what the attester is worth. Until now an attestation
// carried a holder key — a random string that identifies a party consistently and
// proves nothing about who they are. That is enough to say "the same party twice" and
// not enough for a lab to retract what it issued, or for anyone to know a claimed lab
// is that lab.
//
// This follows the W3C Verifiable Credentials model, which is the settled answer:
//
//   - The attester holds a keypair and signs. The signature is the proof, not the name.
//   - A trust registry maps a public key to a real-world identity. Verifiers consult it
//     to decide whether an issuer is recognised.
//   - Retraction is a registry entry rather than a key operation, so losing a key does
//     not make past attestations permanently unretractable.
//
// The part worth being honest about: nothing inside a system can establish that a lab
// is a lab. That comes from outside — for cannabis testing, ISO 17025 accreditation is
// the existing anchor. The registry records who vouched, and a verifier decides whether
// they trust the voucher. We do not vouch, because a registry that certifies its own
// members is not neutral.
//
// SPDX-License-Identifier: Apache-2.0

import { sha256Hex } from './hash.js';
import { canonicalise } from './canonical.js';

export type AttesterIdentity = {
  /** Public key, hex. The stable identifier — a name can change, this cannot. */
  publicKey: string;
  displayName?: string;
  /** What the attester claims to be. Claimed, not verified by us. */
  role?: 'laboratory' | 'inspector' | 'registry' | 'breeder' | 'other';
  /**
   * External accreditation, if any. Recorded, never checked by us — a verifier decides
   * whether the accreditor means anything to them.
   */
  accreditation?: {
    scheme: string;      // e.g. 'ISO/IEC 17025'
    identifier: string;  // the accreditation number
    accreditor: string;  // who issued it
    verifiedAt?: string; // when someone last confirmed it, if ever
  };
};

export type SignedAttestation = {
  attestationId: string;
  type: string;
  /** The record being attested to. */
  subjectCommitment: string;
  attester: AttesterIdentity;
  documentHash: string;
  hashAlgorithm: 'sha256';
  issuedAt: string;
  /** Signature over the canonical form of everything above. */
  signature?: string;
  signatureAlgorithm?: 'ed25519';
};

/** The bytes an attester signs. Canonical, so any implementation reproduces them. */
export const attestationPayload = (a: Omit<SignedAttestation, 'signature' | 'signatureAlgorithm'>): string =>
  canonicalise({
    attestationId: a.attestationId,
    attester: { publicKey: a.attester.publicKey },
    documentHash: a.documentHash,
    hashAlgorithm: a.hashAlgorithm,
    issuedAt: a.issuedAt,
    subjectCommitment: a.subjectCommitment,
    type: a.type,
  });

/** A stable identifier for an attester, derived from their key rather than their name. */
export const attesterId = async (publicKey: string): Promise<string> =>
  `vc_att_${(await sha256Hex(`veilcore:attester:${publicKey}`)).slice(0, 16)}`;

export type RetractionReason = 'issued-in-error' | 'superseded' | 'sample-compromised' | 'other';

/**
 * A retraction.
 *
 * Recorded against the attestation and signed by the same key that issued it, so a
 * holder cannot suppress a retraction and a third party cannot forge one.
 *
 * Deliberately a registry entry rather than a deletion: the attestation happened, and
 * pretending otherwise is the same failure as voiding a record.
 */
export type Retraction = {
  attestationId: string;
  attesterPublicKey: string;
  reason: RetractionReason;
  note?: string;
  retractedAt: string;
  signature?: string;
};

export const retractionPayload = (r: Omit<Retraction, 'signature'>): string =>
  canonicalise({
    attestationId: r.attestationId,
    attesterPublicKey: r.attesterPublicKey,
    reason: r.reason,
    retractedAt: r.retractedAt,
  });

/**
 * How much weight an attestation carries.
 *
 * Reported rather than enforced. A verifier decides what is good enough for them — a
 * registry that ruled on this would be substituting its judgement for theirs, and would
 * stop being neutral the first time the answer was commercially inconvenient.
 */
export type AttestationStrength = 'unsigned' | 'signed' | 'signed-and-accredited';

export const strengthOf = (a: SignedAttestation): AttestationStrength => {
  if (!a.signature) return 'unsigned';
  return a.attester.accreditation ? 'signed-and-accredited' : 'signed';
};
