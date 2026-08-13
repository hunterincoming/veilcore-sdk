// Contesting a record you do not hold.
//
// A holder can correct their own record and an attester can retract their own
// attestation. Neither covers the case that matters most: someone else says the record
// is wrong.
//
// Three properties make this workable rather than a griefing tool.
//
// A challenge NEVER alters the record. It changes what a verifier is told about it. The
// record remains exactly as sealed, because a record a stranger can change is not
// evidence.
//
// A challenger must SEAL A RECORD OF THEIR OWN CLAIM first. It costs them something,
// it is auditable, and it puts their assertion on the same footing as the one they are
// contesting.
//
// And a challenge is SIGNED. An anonymous challenge is free to make and impossible to
// answer, which is the definition of a griefing tool.
//
// SPDX-License-Identifier: Apache-2.0

import { canonicalise } from './canonical.js';

export type ChallengeGround =
  /** The challenger says they held this material earlier. */
  | 'prior-possession'
  /** The challenger says the described descent is wrong. */
  | 'descent'
  /** The challenger says an attestation was not issued as recorded. */
  | 'attestation'
  /** The challenger says the subject is not what the record describes. */
  | 'identity'
  | 'other';

export type ChallengeState =
  /** Filed and signed, not yet answered. */
  | 'open'
  /** The holder has responded. Both statements now travel with the record. */
  | 'answered'
  /** The challenger withdrew it. The challenge remains on record. */
  | 'withdrawn'
  /** Resolved by an authority outside this system - a court, a rights body. */
  | 'resolved';

export type Challenge = {
  challengeId: string;
  /** The record being contested. */
  subjectCommitment: string;
  /**
   * The challenger's own sealed record of their claim. Required: a challenge without
   * one is an assertion with nothing behind it, and this is what makes filing cost
   * something.
   */
  claimCommitment: string;
  ground: ChallengeGround;
  /** Stated plainly, and public. A challenge nobody can read cannot be answered. */
  statement: string;
  challenger: { publicKey: string; displayName?: string };
  filedAt: string;
  state: ChallengeState;
  /** The holder's answer, if given. Never required - silence is not an admission. */
  response?: { statement: string; respondedAt: string; signature?: string };
  /**
   * How it ended, if it did. VeilCore does not adjudicate: this records that an outside
   * authority ruled, and which way, so a verifier can look it up themselves.
   */
  resolution?: { authority: string; reference: string; outcome: string; resolvedAt: string };
  signature?: string;
  signatureAlgorithm?: 'ed25519';
};

/** The bytes a challenger signs. */
export const challengePayload = (c: Omit<Challenge, 'signature' | 'signatureAlgorithm' | 'response' | 'resolution' | 'state'>): string =>
  canonicalise({
    challengeId: c.challengeId,
    challenger: { publicKey: c.challenger.publicKey },
    claimCommitment: c.claimCommitment,
    filedAt: c.filedAt,
    ground: c.ground,
    statement: c.statement,
    subjectCommitment: c.subjectCommitment,
  });

/**
 * What a verifier is told about a record that has been challenged.
 *
 * Deliberately not a verdict. The record is reported as contested, with the ground and
 * whether the holder answered, and the verifier decides what that is worth to them. A
 * registry that ruled on this would be substituting its judgement for a court's.
 */
export type ContestedStatus = {
  contested: boolean;
  open: number;
  answered: number;
  resolved: number;
  grounds: ChallengeGround[];
  /** Plain words for a reader who is not a lawyer. */
  summary: string;
};

export const contestedStatus = (challenges: Challenge[]): ContestedStatus => {
  const live = challenges.filter((c) => c.state !== 'withdrawn');
  const open = live.filter((c) => c.state === 'open').length;
  const answered = live.filter((c) => c.state === 'answered').length;
  const resolved = live.filter((c) => c.state === 'resolved').length;

  let summary: string;
  if (!live.length) {
    summary = 'Nobody has contested this record.';
  } else if (resolved && !open && !answered) {
    summary = 'This record was contested and the matter was resolved outside this system. The resolution is recorded and you can check it with the authority named.';
  } else if (open) {
    summary = `Contested. ${open} challenge${open > 1 ? 's are' : ' is'} open and unanswered. A challenge is an assertion by another party, not a finding - the challenger has sealed a record of their own claim, and you can read both.`;
  } else {
    summary = 'Contested, and the holder has answered. Both statements travel with the record. Neither has been adjudicated here.';
  }

  return {
    contested: live.length > 0,
    open, answered, resolved,
    grounds: [...new Set(live.map((c) => c.ground))],
    summary,
  };
};
