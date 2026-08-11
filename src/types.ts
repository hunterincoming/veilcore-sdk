// The VeilCore record envelope.
//
// The envelope is domain-blind: no field here names a crop, an animal, a plant part or
// a cannabis concept. The test for any proposed envelope field is whether a Dutch
// orchid propagator or a wagyu herd book would need it too. If not, it belongs in a
// profile.
//
// SPDX-License-Identifier: Apache-2.0

export const FORMAT_VERSION = '0.1';
export const COMMITMENT_ALGORITHM = 'sha256/canonical-json/v1';

export type SubjectType =
  | 'plant-genetic-material'
  | 'animal-genetic-material'
  | 'plant-variety'
  | 'other';

/** Where a commitment is anchored, if anywhere. */
export type Anchor = {
  chain: string;
  /** `undeployed` is the honest state for a record sealed locally and never settled. */
  network: 'mainnet' | 'preview' | 'preprod' | 'undeployed';
  contractAddress?: string;
  txHash?: string;
  blockHeight?: number;
  anchoredAt?: string;
  /**
   * How the record commitment is bound to this chain. Chain-specific by design — the
   * record commitment itself is plain SHA-256 and requires no chain runtime.
   */
  commitmentAlgorithm?: string;
};

export type Attester = { id: string; displayName?: string; publicKey?: string };

export type AttestationType =
  | 'genetic-fingerprint'
  | 'laboratory-report'
  | 'inspection'
  | 'chain-of-custody'
  | 'self-documentation'
  | 'other';

/** A third party asserting something about the subject. The document never enters the record. */
export type Attestation = {
  attestationId: string;
  type: AttestationType;
  attester: Attester;
  documentHash: string;
  hashAlgorithm: 'sha256';
  issuedAt: string;
  signature?: string;
  /** Set only by the attester. A holder cannot suppress a retraction. */
  retractedBy?: string;
};

/** Descent. Not a cannabis idea, so it lives in the envelope. */
export type ParentRef = {
  parentRecordId?: string;
  /** Binds to content rather than an identifier, so a renamed parent still resolves. */
  parentCommitment?: string;
  /** Profile-defined vocabulary. Cannabis: seed-parent. Livestock: sire. */
  role?: string;
  /** A self-declared parent and a lab-confirmed one are different evidence. */
  declaredBy: 'holder' | 'attester';
  verified: boolean;
  /** A free-typed parent where no record exists yet. */
  name?: string;
};

export type Terms = {
  termsRef: string;
  termsHash: string;
  /** Whether this creates an obligation that travels to descendants. */
  encumbers: boolean;
  status: 'draft' | 'sent' | 'active' | 'expired' | 'revoked';
};

export type Supersedes = {
  recordId: string;
  reason: string;
  /** Whether descendants are affected. Classified by the changed field, not chosen. */
  descentSeverity: 'cosmetic' | 'material';
  /** Whether issued terms are affected. A name change can be one and not the other. */
  termsSeverity: 'cosmetic' | 'material';
  effectiveAt: string;
  /** Each party may only correct what they asserted. */
  correctedBy: 'holder' | 'attester' | 'challenge-resolution';
};

export type JurisdictionBinding = {
  authority: string;
  identifier: string;
  identifierScheme?: string;
  status?: 'applied' | 'granted' | 'lapsed' | 'withdrawn';
};

export type Envelope = {
  formatVersion: string;
  recordId: string;
  subjectType: SubjectType;
  /** Profile identifier and version, e.g. veilcore/profile/cannabis/v0.1 */
  profile: string;
  commitment: string;
  commitmentAlgorithm: string;
  /** Not committed — the anchor is about the commitment, so it cannot be inside it. */
  anchor: Anchor;
  sealedAt: string;
  holder: { id: string; displayName?: string; publicKey?: string };
  attestations?: Attestation[];
  parents?: ParentRef[];
  /** Not committed — terms are issued and revoked after sealing. */
  terms?: Terms;
  supersedes?: Supersedes;
  jurisdictionBindings?: JurisdictionBinding[];
  /** The domain payload. Opaque to the envelope. */
  profileData: Record<string, unknown>;
  /** Namespaced escape hatch. Keys must be reverse-DNS. */
  extensions?: Record<string, unknown>;
};
