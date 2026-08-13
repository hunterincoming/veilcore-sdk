// Reading anchors, across jurisdictions.
//
// A commitment can be bound to a time by more than one mechanism, and jurisdictions do
// not agree on which they recognise. Rather than encoding each jurisdiction's rules,
// this format lets a record carry several anchors and lets the reader take the one that
// counts where they are.
//
// SPDX-License-Identifier: Apache-2.0

import type { Anchor, Envelope } from './types.js';

/** Anchors on a record, normalised to an array whichever form was used. */
export const anchorsOf = (env: Envelope): Anchor[] => {
  const a = env.anchor as Anchor | Anchor[] | undefined;
  if (!a) return [];
  return Array.isArray(a) ? a : [a];
};

/** Anchors that actually establish a time, as opposed to declaring an intention to. */
export const effectiveAnchors = (env: Envelope): Anchor[] =>
  anchorsOf(env).filter((a) => {
    const kind = a.kind ?? 'ledger';
    if (kind === 'ledger') return Boolean(a.txHash) && a.network !== 'undeployed';
    if (kind === 'rfc3161') return Boolean(a.token);
    if (kind === 'notarial') return Boolean(a.notary?.reference);
    return false;
  });

/**
 * What a reader in a given jurisdiction can rely on.
 *
 * Reported, not decided. This says which anchors exist and what is generally said about
 * them; whether a particular court accepts a particular anchor is a question for counsel
 * in that jurisdiction, and this format takes no position on it.
 */
export type AnchorStanding = {
  kind: string;
  /** Where the strongest recognition of this anchor type is usually found. */
  note: string;
  /** Whether a legal presumption attaches, where one is documented. */
  presumption: boolean;
};

export const standingOf = (a: Anchor): AnchorStanding => {
  const kind = a.kind ?? 'ledger';

  if (kind === 'rfc3161') {
    const qualified = Boolean(a.qualified?.scheme);
    return {
      kind: 'rfc3161',
      presumption: qualified,
      note: qualified
        ? `Timestamp token from ${a.tsa ?? 'a Time Stamping Authority'}, stated as qualified under ${a.qualified?.scheme}. Where that status holds, eIDAS Article 42 attaches a presumption of accuracy across EU member states and the burden falls on whoever disputes the date. Verify the provider's listing before relying on this.`
        : `Timestamp token from ${a.tsa ?? 'a Time Stamping Authority'} without stated qualified status. Admissible, but carrying no presumption: it can be challenged like any other evidence.`,
    };
  }

  if (kind === 'notarial') {
    return {
      kind: 'notarial',
      presumption: true,
      note: `Timestamp applied by ${a.notary?.name ?? 'a notary'} in ${a.notary?.jurisdiction ?? 'an unnamed jurisdiction'}. Weight follows local rules on notarial acts, which in most civil-law systems is considerable.`,
    };
  }

  return {
    kind: 'ledger',
    presumption: false,
    note: `Published on ${a.chain}${a.network ? ` (${a.network})` : ''}. No general presumption attaches, with exceptions: Italian Law 12/2019 grants blockchain timestamps the effect of an eIDAS timestamp, Chinese Internet Courts have accepted blockchain evidence since 2018, and several US states have enacted authentication presumptions. Elsewhere the date is provable but is proved rather than presumed.`,
  };
};

/**
 * A plain summary of how well dated a record is.
 *
 * Deliberately conservative: where no anchor establishes a time, that is stated, because
 * a reader assuming otherwise would be relying on something that is not there.
 */
export const datingSummary = (env: Envelope): string => {
  const live = effectiveAnchors(env);
  if (!live.length) {
    return 'This record is intact but not anchored. Its date rests on whoever holds it, not on anything independent.';
  }
  const kinds = live.map((a) => standingOf(a));
  const presumed = kinds.filter((k) => k.presumption);
  if (presumed.length) {
    return `Anchored ${live.length} way${live.length > 1 ? 's' : ''}, including ${presumed.length} carrying a documented legal presumption of accuracy in at least one jurisdiction.`;
  }
  return `Anchored ${live.length} way${live.length > 1 ? 's' : ''}. The date is independently provable; whether it is presumed depends on where you are.`;
};
