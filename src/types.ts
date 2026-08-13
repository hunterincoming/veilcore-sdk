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

/**
 * How a commitment is bound to a time.
 *
 * `ledger` publishes the commitment (or a batch root containing it) in a public chain.
 * `rfc3161` is a signed timestamp token from a Time Stamping Authority. Where that TSA
 * is a Qualified Trust Service Provider on an EU trusted list, eIDAS Article 42 attaches
 * a presumption of accuracy and shifts the burden to whoever disputes the date.
 * `notarial` records a timestamp applied by a notary or equivalent officer.
 */
export type AnchorKind = 'ledger' | 'rfc3161' | 'notarial';

/** Where a commitment is anchored, if anywhere. */
export type Anchor = {
  /** Defaults to `ledger` when absent, for records written before this field existed. */
  kind?: AnchorKind;
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

  // For kind: 'rfc3161'
  /** The timestamp token, base64. Verifiable against the TSA's certificate. */
  token?: string;
  /** The Time Stamping Authority that issued it. */
  tsa?: string;
  /** Whether that TSA holds qualified status, and under which scheme. */
  qualified?: { scheme: string; trustedList?: string };

  // For kind: 'notarial'
  notary?: { name: string; jurisdiction: string; reference: string };
};

/**
 * Every anchor on a record.
 *
 * A commitment may be bound to a time by more than one mechanism, and different
 * jurisdictions recognise different ones. An EU court applies the eIDAS presumption to a
 * qualified timestamp; Italian law grants blockchain anchors the same effect under Law
 * 12/2019; Chinese Internet Courts have accepted blockchain evidence since 2018; a US
 * court authenticates either under FRE 901(b)(9).
 *
 * Carrying several costs almost nothing, because each binds the same commitment. It also
 * keeps jurisdiction-specific rules out of this format entirely: a court reads the
 * anchor it recognises and ignores the rest.
 */
export type Anchors = Anchor[];

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
  /**
   * What every subject has, whatever domain it is from.
   *
   * These are in the envelope rather than in a profile because the alternative is every
   * profile redefining them, which is how definitions drift. UPOV has run this shape
   * since 1961: conditions that apply to every variety live in the convention, and what
   * varies by species lives in a Test Guideline.
   *
   * The test each of these passed: would an ornamental propagator, a livestock herd
   * book, and a microbial culture collection all need it.
   */
  subject?: {
    /** What it is called. A variety denomination, an animal name, a strain designation. */
    name?: string;
    /** An internal designation, which usually precedes a public name. */
    internalDesignation?: string;
    /** Species or equivalent taxonomic identifier. */
    taxon?: string;
    /**
     * Who claims to have produced or selected it. Deliberately not "breeder": a culture
     * collection has a depositor and a herd book has a keeper.
     */
    originator?: string;
    /**
     * When the holder says it came into being. Distinct from sealedAt, and the field a
     * prior-possession argument turns on.
     */
    claimedCreationDate?: string;
  };

  /**
   * What distinguishes this subject from others.
   *
   * Every domain identifies subjects by something measurable, and the shape is the same
   * everywhere: a named method, and values produced by it. What the values mean is the
   * profile's business; that they exist and are committed is the envelope's.
   *
   * Committed like any other field, so a holder can show identification data to one
   * examiner and prove afterwards that what they showed is what was sealed. It is never
   * published.
   */
  identification?: {
    /** How the subject was identified. */
    method?: 'morphological' | 'molecular-marker' | 'sequence' | 'phenotypic' | 'other';
    /** A named panel or protocol, where one exists. */
    panel?: string;
    /** The values themselves. Structure is the profile's business. */
    data?: unknown;
    /** Who produced them. Substantiate with a signed attestation from that party. */
    performedBy?: string;
    performedOn?: string;
    /** SHA-256 of a report held by the holder. The report never enters the record. */
    reportHash?: string;
  };

  /**
   * External registrations. Recorded, never verified by any registry implementing this
   * format.
   */
  registrations?: {
    authority: string;
    reference: string;
    status?: 'pending' | 'granted' | 'lapsed' | 'withdrawn' | 'refused';
    filedOn?: string;
  }[];

  /** The domain payload. Opaque to the envelope. */
  profileData: Record<string, unknown>;
  /** Namespaced escape hatch. Keys must be reverse-DNS. */
  extensions?: Record<string, unknown>;
};
