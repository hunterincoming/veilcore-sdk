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

/**
 * Anchors complete enough to be checked, as opposed to declaring an intention to anchor.
 *
 * NOT VERIFIED HERE. This looks only at what the record states: a transaction hash, a
 * token, a notarial reference. Whether the transaction published this commitment, whether
 * the token's signature and imprint check out, and whether the notary recorded it are
 * lookups (SPEC 9.2) this package does not make. A record can state an anchor that does
 * not exist.
 */
export const effectiveAnchors = (env: Envelope): Anchor[] =>
  anchorsOf(env).filter((a) => {
    const kind = a.kind ?? 'ledger';
    if (kind === 'ledger') return Boolean(a.txHash) && a.network !== 'undeployed';
    if (kind === 'rfc3161') return Boolean(a.token);
    if (kind === 'notarial') return Boolean(a.notary?.reference);
    if (kind === 'opentimestamps') return Boolean(a.ots);
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
        ? `Timestamp token from ${a.tsa ?? 'a Time Stamping Authority'}, stated as qualified under ${a.qualified?.scheme}. Where that status holds, eIDAS Article 41(2) gives a qualified timestamp a presumption of accuracy across EU member states, and the burden falls on whoever disputes the date. Not checked here: verify the token's signature and imprint, and the provider's trusted-list entry, before relying on this.`
        : `Timestamp token from ${a.tsa ?? 'a Time Stamping Authority'} without stated qualified status. Admissible, but carrying no presumption: it can be challenged like any other evidence.`,
    };
  }

  if (kind === 'opentimestamps') {
    return {
      kind: 'opentimestamps',
      presumption: false,
      note: `An OpenTimestamps proof that ${a.stamps ?? 'the commitment'} existed by the time of a Bitcoin block, through ${a.calendars?.length ? a.calendars.join(', ') : 'public calendar servers'}. Independent of VeilCore and of Midnight: check it with the OpenTimestamps client (ots verify) against Bitcoin. No general presumption attaches; a French court accepted a blockchain timestamp as evidence of authorship in 2025. A fresh proof is pending until the calendar's transaction confirms (ots upgrade). Not checked here.`,
    };
  }

  if (kind === 'notarial') {
    return {
      kind: 'notarial',
      // Weight varies too much by jurisdiction to report a presumption generally: a civil-law
      // notarial act and a US notary's stamp are very different things.
      presumption: false,
      note: `Timestamp applied by ${a.notary?.name ?? 'a notary'} in ${a.notary?.jurisdiction ?? 'an unnamed jurisdiction'}. Weight follows local rules on notarial acts: considerable in most civil-law systems, much less where a notary only witnesses a signature. Not checked here.`,
    };
  }

  return {
    kind: 'ledger',
    presumption: false,
    note: `Stated as published on ${a.chain}${a.network ? ` (${a.network})` : ''}. No general presumption attaches. Italy's Law 12/2019 (Art. 8-ter) gives distributed-ledger timestamps the effect of an ordinary eIDAS electronic timestamp (Art. 41(1), no presumption), subject to technical standards; Chinese courts have accepted blockchain evidence since 2018; in the US, Vermont (12 V.S.A. §1913) has a statute on blockchain records. Elsewhere the date is provable but is proved rather than presumed. Not checked here: confirm the transaction published this commitment (SPEC 9.2).`,
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
    return 'This record states no anchor that could be checked. Its date rests on whoever holds it, not on anything independent.';
  }
  const kinds = live.map((a) => standingOf(a));
  const presumed = kinds.filter((k) => k.presumption);
  if (presumed.length) {
    return `States ${live.length} anchor${live.length > 1 ? 's' : ''}, including ${presumed.length} stated as qualified, which would carry a legal presumption of accuracy in the EU if confirmed. None is checked by this summary: confirm each (SPEC 9.2) before relying on the date.`;
  }
  return `States ${live.length} anchor${live.length > 1 ? 's' : ''}. If confirmed (SPEC 9.2), the date is independently provable; whether it is presumed depends on where you are.`;
};
