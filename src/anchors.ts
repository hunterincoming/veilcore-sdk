// Reading anchors, across jurisdictions.
//
// A commitment can be bound to a time by more than one mechanism, and jurisdictions do
// not agree on which they recognise. Rather than encoding each jurisdiction's rules,
// this format lets a record carry several anchors and lets the reader take the one that
// counts where they are.
//
// SPDX-License-Identifier: Apache-2.0

import type { Anchor, AnchorKind, Envelope } from './types.js';
import { verifyTimestampToken, TIMESTAMP_NOT_CHECKED, type TimestampVerification } from './rfc3161.js';

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
 * token, a notarial reference. A record can state an anchor that does not exist. To check
 * one, use `verifyAnchor`: it verifies an RFC 3161 token offline, and for every other kind
 * says what has to be looked up (SPEC 9.2).
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
        ? `Timestamp token from ${a.tsa ?? 'a Time Stamping Authority'}, stated as qualified under ${a.qualified?.scheme}. Where that status holds, eIDAS Article 41(2) gives a qualified timestamp a presumption of accuracy across EU member states, and the burden falls on whoever disputes the date. Not checked by this note: verifyAnchor checks the token's imprint, signature and time-stamping key usage; the certificate chain, the provider's trusted-list entry and revocation are not checked by this package, and must be before relying on the presumption.`
        : `Timestamp token from ${a.tsa ?? 'a Time Stamping Authority'} without stated qualified status. Admissible, but carrying no presumption: it can be challenged like any other evidence. Not checked by this note: verifyAnchor checks the token itself, but not who issued its certificate.`,
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

/** The outcome of checking one anchor. */
export type AnchorVerification = {
  kind: AnchorKind;
  /**
   * `checked`: verified here, offline (an RFC 3161 token whose checks all passed).
   * `failed`: checked here and did not hold; do not rely on this anchor.
   * `lookup`: stated, and only an outside lookup can confirm it (ledger, notary, Bitcoin).
   * `incomplete`: declares an intention to anchor but has nothing to check.
   */
  status: 'checked' | 'failed' | 'lookup' | 'incomplete';
  /** What was found, or what to do, in plain words. */
  what: string;
  /** For `rfc3161`, the token check in full. */
  timestamp?: TimestampVerification;
  /** What even a `checked` anchor leaves open. */
  notChecked: string[];
};

const hexBytes = (h: string): Uint8Array | undefined => {
  if (!/^[0-9a-f]{64}$/.test(h)) return undefined;
  return Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
};

/**
 * Check one anchor as far as can be done without a network.
 *
 * `stampedBytes` is what the anchor stamps. It defaults to the 32 raw bytes of the
 * record's commitment; for an anchor carried on an inclusion proof, pass the 32 raw bytes
 * of the batch root instead (SPEC 3.2).
 *
 * Only `rfc3161` is verified here: the token's imprint, its signature and its signer's
 * time-stamping key usage. Whether that signer is a TSA anyone should trust (chain,
 * trusted list, revocation) is not checked, and is listed in `notChecked`. Every other
 * kind is reported as a lookup, with what to look up.
 */
export const verifyAnchor = async (env: Envelope, anchor: Anchor, stampedBytes?: Uint8Array): Promise<AnchorVerification> => {
  const kind = anchor.kind ?? 'ledger';
  if (kind === 'rfc3161') {
    if (!anchor.token) {
      return { kind, status: 'incomplete', what: 'rfc3161 anchor with no token: nothing to check', notChecked: [] };
    }
    const stamped = stampedBytes ?? hexBytes(env.commitment);
    if (!stamped) {
      return { kind, status: 'failed', what: 'the record commitment is not 64 lowercase hex characters, so there is nothing to compare the token with', notChecked: [...TIMESTAMP_NOT_CHECKED] };
    }
    const t = await verifyTimestampToken(anchor.token, stamped);
    return {
      kind,
      status: t.ok ? 'checked' : 'failed',
      what: t.ok
        ? `RFC 3161 token checked: it stamps these bytes at ${t.genTime}, signed by "${t.signerSubject}". Not checked: ${t.notChecked.join('; ')}.`
        : `RFC 3161 token did not check out: ${t.checks.filter((c) => !c.ok).map((c) => c.what).join('; ')}`,
      timestamp: t,
      notChecked: t.notChecked,
    };
  }
  if (kind === 'ledger') {
    if (!anchor.txHash || anchor.network === 'undeployed') {
      return { kind, status: 'incomplete', what: `ledger anchor on ${anchor.chain} (${anchor.network}) with no transaction: nothing to confirm`, notChecked: [] };
    }
    return {
      kind,
      status: 'lookup',
      what: `confirm transaction ${anchor.txHash} on ${anchor.chain} (${anchor.network}) published this commitment or its batch root (SPEC 9.2)`,
      notChecked: ['the transaction, looked up on the ledger'],
    };
  }
  if (kind === 'opentimestamps') {
    if (!anchor.ots) return { kind, status: 'incomplete', what: 'OpenTimestamps anchor with no proof', notChecked: [] };
    return { kind, status: 'lookup', what: 'confirm the OpenTimestamps proof against Bitcoin: `ots upgrade`, then `ots verify`', notChecked: ['the Bitcoin attestation'] };
  }
  if (kind === 'notarial') {
    if (!anchor.notary?.reference) return { kind, status: 'incomplete', what: 'notarial anchor with no reference', notChecked: [] };
    return { kind, status: 'lookup', what: `confirm reference ${anchor.notary.reference} with ${anchor.notary.name} (${anchor.notary.jurisdiction})`, notChecked: ['the notarial act, confirmed with the notary'] };
  }
  return { kind: kind as AnchorKind, status: 'incomplete', what: `unknown anchor kind ${String(kind)}`, notChecked: [] };
};

/**
 * A plain summary of how well dated a record is.
 *
 * Deliberately conservative: where no anchor establishes a time, that is stated, because
 * a reader assuming otherwise would be relying on something that is not there.
 */
export const datingSummary = (env: Envelope, results?: AnchorVerification[]): string => {
  const live = effectiveAnchors(env);
  if (!live.length) {
    return 'This record states no anchor that could be checked. Its date rests on whoever holds it, not on anything independent.';
  }
  if (results) return checkedSummary(live, results);
  const kinds = live.map((a) => standingOf(a));
  const presumed = kinds.filter((k) => k.presumption);
  if (presumed.length) {
    return `States ${live.length} anchor${live.length > 1 ? 's' : ''}, including ${presumed.length} stated as qualified, which would carry a legal presumption of accuracy in the EU if confirmed. None is checked by this summary: confirm each (SPEC 9.2) before relying on the date.`;
  }
  return `States ${live.length} anchor${live.length > 1 ? 's' : ''}. If confirmed (SPEC 9.2), the date is independently provable; whether it is presumed depends on where you are.`;
};

// With results from verifyAnchor: say which dates were checked here and which are only stated.
const checkedSummary = (live: Anchor[], results: AnchorVerification[]): string => {
  const checked = results.filter((r) => r.status === 'checked');
  const failed = results.filter((r) => r.status === 'failed');
  const lookup = results.filter((r) => r.status === 'lookup');
  const n = (k: number, one: string, many = one + 's'): string => `${k} ${k === 1 ? one : many}`;
  const parts = [`States ${n(live.length, 'anchor')}.`];
  if (checked.length) {
    const times = checked.map((r) => r.timestamp?.genTime).filter((t): t is string => Boolean(t)).sort();
    parts.push(
      `Checked: ${n(checked.length, 'timestamp token')}${times.length ? `, the earliest at ${times[0]}` : ''} (imprint, signature and time-stamping key usage verified; the certificate chain, trusted-list status and revocation were not checked).`,
    );
  }
  if (failed.length) parts.push(`Failed: ${n(failed.length, 'anchor')} did not check out and should not be relied on.`);
  if (lookup.length) parts.push(`Stated only: ${n(lookup.length, 'anchor')} can be confirmed only by a lookup (SPEC 9.2).`);
  if (live.some((a) => a.qualified?.scheme)) {
    parts.push('Qualified status is stated, not checked: confirm it against the EU trusted list before relying on a presumption.');
  }
  if (!checked.length && !lookup.length) parts.push('Nothing establishes when this record was made.');
  return parts.join(' ');
};
