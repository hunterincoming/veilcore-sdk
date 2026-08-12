// Corrections.
//
// Records are never edited and never voided. A correction issues a NEW record that
// supersedes the old one, and both remain — because a record that can be quietly
// changed is not evidence, and voiding is rewriting under another name.
//
// The rule that matters: severity is classified by WHICH FIELD CHANGED, never chosen by
// the holder. If the holder picks, every correction is cosmetic — nobody marks their own
// correction as the kind that invalidates their downstream agreements.
//
// Two severities, not one. A cultivar name change is cosmetic for descent (the material
// did not change) and material for terms (the name may be the licensed thing). Collapsing
// them into a single flag forces a wrong answer in one direction or the other.
//
// SPDX-License-Identifier: Apache-2.0

import type { Envelope } from './types.js';

export type Severity = 'cosmetic' | 'material';

export type SeverityClass = {
  /** Whether descendants are affected. */
  descent: Severity;
  /** Whether issued terms are affected. */
  terms: Severity;
};

/**
 * Field classification, by construction rather than by judgement at correction time.
 *
 * Envelope fields that identify the subject or its evidence are material for descent:
 * changing them changes what a descendant descends from. Profile fields that describe
 * the subject are cosmetic for descent — the plant is the same plant.
 */
const CLASSIFICATION: Record<string, SeverityClass> = {
  // Envelope — identity and evidence.
  'parents': { descent: 'material', terms: 'material' },
  'attestations': { descent: 'material', terms: 'material' },
  'sealedAt': { descent: 'material', terms: 'material' },
  'holder': { descent: 'material', terms: 'material' },
  'subjectType': { descent: 'material', terms: 'material' },
  'profile': { descent: 'material', terms: 'material' },

  // Profile — description.
  'profileData.cultivarName': { descent: 'cosmetic', terms: 'material' },
  'profileData.breederName': { descent: 'cosmetic', terms: 'material' },
  'profileData.breedingMethod': { descent: 'material', terms: 'cosmetic' },
  'profileData.claimedCreationDate': { descent: 'cosmetic', terms: 'material' },
  'profileData.notes': { descent: 'cosmetic', terms: 'cosmetic' },
  'profileData.internalReference': { descent: 'cosmetic', terms: 'cosmetic' },
  'profileData.phenotypeSelection': { descent: 'cosmetic', terms: 'cosmetic' },
};

/** Anything unclassified is material. An unknown change is not assumed harmless. */
const UNKNOWN: SeverityClass = { descent: 'material', terms: 'material' };

const flatten = (obj: unknown, prefix = ''): Record<string, unknown> => {
  const out: Record<string, unknown> = {};
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    if (prefix) out[prefix] = obj;
    return out;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) Object.assign(out, flatten(v, path));
    else out[path] = v;
  }
  return out;
};

export type FieldChange = { field: string; from: unknown; to: unknown; severity: SeverityClass };

/** Which fields differ between two envelopes, and how severe each change is. */
export const diffRecords = (before: Envelope, after: Envelope): FieldChange[] => {
  const a = flatten(before);
  const b = flatten(after);
  const fields = new Set([...Object.keys(a), ...Object.keys(b)]);
  const changes: FieldChange[] = [];

  for (const f of fields) {
    // The commitment and anchor necessarily differ between a record and its
    // replacement; they describe the record rather than the subject.
    if (f === 'commitment' || f.startsWith('anchor') || f === 'recordId' || f.startsWith('supersedes')) continue;
    if (JSON.stringify(a[f]) === JSON.stringify(b[f])) continue;
    changes.push({ field: f, from: a[f], to: b[f], severity: CLASSIFICATION[f] ?? UNKNOWN });
  }
  return changes;
};

/**
 * The overall severity of a correction: the worst severity across every changed field.
 *
 * Taking the maximum rather than an average is deliberate. One material change makes the
 * correction material regardless of how many cosmetic ones accompany it.
 */
export const classifyCorrection = (changes: FieldChange[]): SeverityClass => ({
  descent: changes.some((c) => c.severity.descent === 'material') ? 'material' : 'cosmetic',
  terms: changes.some((c) => c.severity.terms === 'material') ? 'material' : 'cosmetic',
});

/** Build the supersedes block for a correcting record. */
export const supersedesFor = (
  before: Envelope,
  after: Envelope,
  reason: string,
  correctedBy: 'holder' | 'attester' | 'challenge-resolution',
): {
  recordId: string; reason: string;
  descentSeverity: Severity; termsSeverity: Severity;
  effectiveAt: string; correctedBy: string; changedFields: string[];
} => {
  const changes = diffRecords(before, after);
  const sev = classifyCorrection(changes);
  return {
    recordId: before.recordId,
    reason,
    descentSeverity: sev.descent,
    termsSeverity: sev.terms,
    effectiveAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    correctedBy,
    // Named, not valued: a downstream party learns what kind of change occurred without
    // learning the contents of a record they were never granted.
    changedFields: changes.map((c) => c.field),
  };
};
