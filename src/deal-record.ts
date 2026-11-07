// Checking a VeilCore deal record (SPEC 11.10): the signed messages of one license deal,
// as either side saves them (the web app's "Download the deal's record", and the
// `dealRecords` of its backup file). Nothing from VeilCore is needed to check one.
//
// What it is for: showing someone else (a buyer, a court, a lender) a royalty history the
// payer signed, not a spreadsheet the payee typed. Each statement is signed by the
// licensee; each acceptance and each "received" by the licensor; each "paid" by the
// licensee. A line counts as settled only when both sides signed for the same money, and that
// money is exactly what the accepted statement owes.
//
// Order: the registry's `seq`, which each saved message carries beside it; never the senders'
// own signed times, which either side can set to anything. With seq, a reply or payment signed
// with an earlier time can't jump ahead of one already there. A record saved before records kept
// seq is read in signed-time order, and the result says so (`order`).
//
// What it cannot show: who holds the two keys. One person can make both and sign a whole
// deal with themselves. The record proves the messages are unchanged and which key said
// what; that the licensee is a real, separate party is for the reader to confirm with them.
//
// SPDX-License-Identifier: Apache-2.0

import { canonicalise } from './canonical.js';
import { verifyEd25519 } from './signing.js';

export const DEAL_RECORD_FORMAT = 'veilcore/deal-record/v1';
/** Prefixed to the canonical JSON of each message before signing. */
export const DEAL_MESSAGE_DOMAIN = 'veilcore/deal-message/v1\n';

type Side = 'issuer' | 'licensee';
type Obj = Record<string, unknown>;

export type DealPayment = { amount: string; currency: string; method: string; reference: string; paidOn: string };

export type DealStatementLine = {
  statementId: string;
  periodFrom: string;
  periodTo: string;
  amountOwed: string;
  currency: string;
  /** The statement's signature: what replies, payments and confirmations name. */
  signature: string;
  reply?: 'accepted' | 'disputed';
  /** Tax the statement declared withheld: what is to pay is amountOwed less this. */
  taxWithheld?: string;
  paid?: DealPayment;
  /** The payment was less than the accepted amount, or in another currency: what is still owed. */
  short?: string;
  received?: { amount: string; currency: string };
  /**
   * The statement was accepted, the licensee signed that they paid exactly what it owes, and the
   * licensor signed that the same amount arrived.
   */
  settled: boolean;
  notes: string[];
};

export type DealRecordCheck = {
  license?: { commitment: string; issuerRecord: string };
  keys: { issuer: string; licensee: string };
  messages: number;
  /** Messages whose signature verifies under the key of the side they name. */
  verified: number;
  /**
   * How the deal was ordered: 'registry' (every message carries the registry's seq) or
   * 'signed-time' (an older record without it: the senders' own clocks, which either side sets).
   */
  order: 'registry' | 'signed-time';
  /** Messages that don't count, and why. */
  rejected: { index: number; type: string; reason: string }[];
  /** Signed and verified, but of a kind this version doesn't read. */
  unread: { index: number; type: string }[];
  statements: DealStatementLine[];
  /** Per currency, what both sides signed as paid and received. */
  settled: Record<string, string>;
  /** Per currency, what accepted statements still owe (the rest of a short payment included). */
  open: Record<string, string>;
  /** About the record as a whole (both sides one key, an unreadable file...). */
  problems: string[];
};

const isObj = (x: unknown): x is Obj => typeof x === 'object' && x !== null && !Array.isArray(x);
const text = (x: unknown, max = 200): x is string => typeof x === 'string' && x.length > 0 && x.length <= max;
const hex = (x: unknown, len: number): x is string => typeof x === 'string' && new RegExp(`^[0-9a-f]{${len}}$`).test(x);
const day = (x: unknown): x is string => typeof x === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(x);
const DEC = /^(0|[1-9]\d{0,29})(\.\d{1,18})?$/;
const dec = (x: unknown): x is string => typeof x === 'string' && DEC.test(x);

// ---- exact decimal sums (amounts are decimal strings, never floats) --------------------

const SCALE = 18;
const toUnits = (s: string): bigint => {
  const [w, f = ''] = s.split('.');
  return BigInt(w) * 10n ** BigInt(SCALE) + BigInt((f + '0'.repeat(SCALE)).slice(0, SCALE));
};
const fromUnits = (u: bigint): string => {
  const w = u / 10n ** BigInt(SCALE);
  const f = (u % 10n ** BigInt(SCALE)).toString().padStart(SCALE, '0').replace(/0+$/, '');
  return f ? `${w}.${f}` : `${w}`;
};
/** Whether two decimal strings are the same amount ("10" and "10.00" are). */
export const sameAmount = (a: string, b: string): boolean => dec(a) && dec(b) && toUnits(a) === toUnits(b);
const add = (sums: Map<string, bigint>, currency: string, amount: string) =>
  sums.set(currency, (sums.get(currency) ?? 0n) + toUnits(amount));
const sub = (a: string, b: string): bigint => toUnits(a) - toUnits(b);
/** What a statement leaves to pay: what it owes less the tax it declared withheld. */
const toPay = (l: { amountOwed: string; taxWithheld?: string }): string =>
  l.taxWithheld && sub(l.amountOwed, l.taxWithheld) >= 0n ? fromUnits(sub(l.amountOwed, l.taxWithheld)) : fromUnits(toUnits(l.amountOwed));
const asRecord = (sums: Map<string, bigint>): Record<string, string> =>
  Object.fromEntries([...sums].sort(([a], [b]) => (a < b ? -1 : 1)).map(([c, u]) => [c, fromUnits(u)]));

/** The exact text a deal message's signature covers. */
export const dealMessagePayload = (message: unknown): string => DEAL_MESSAGE_DOMAIN + canonicalise(message);

/** Who may send each kind of message. Others don't count. */
const SENDER: Record<string, Side | 'either'> = {
  terms: 'issuer',
  agree: 'licensee',
  'plant-record': 'licensee',
  payout: 'issuer',
  statement: 'licensee',
  reply: 'issuer',
  paid: 'licensee',
  received: 'issuer',
  credential: 'issuer',
  // Handing a license on (the web app's hand-on.ts): the holder asks, the licensor names the
  // new holder's commitment, or calls that off.
  'handon-ask': 'licensee',
  handon: 'issuer',
  'handon-off': 'issuer',
};

/**
 * Check a deal record: every signature, who sent what, and which statements both sides
 * signed as settled. Never throws; a file that isn't a deal record comes back with a
 * problem and nothing verified.
 */
export const checkDealRecord = async (record: unknown): Promise<DealRecordCheck> => {
  const empty = (problem: string): DealRecordCheck => ({
    keys: { issuer: '', licensee: '' },
    order: 'signed-time',
    messages: 0,
    verified: 0,
    rejected: [],
    unread: [],
    statements: [],
    settled: {},
    open: {},
    problems: [problem],
  });
  if (!isObj(record) || record.v !== DEAL_RECORD_FORMAT) return empty(`not a ${DEAL_RECORD_FORMAT} file`);
  const keys = isObj(record.keys) ? record.keys : {};
  if (!hex(keys.issuer, 64) || !hex(keys.licensee, 64)) return empty('the record does not name both keys');
  const out: DealRecordCheck = {
    keys: { issuer: keys.issuer, licensee: keys.licensee },
    order: 'signed-time',
    messages: 0,
    verified: 0,
    rejected: [],
    unread: [],
    statements: [],
    settled: {},
    open: {},
    problems: [],
  };
  const lic = record.license;
  if (isObj(lic) && text(lic.commitment) && text(lic.issuerRecord))
    out.license = { commitment: lic.commitment, issuerRecord: lic.issuerRecord };
  if (keys.issuer === keys.licensee)
    out.problems.push('Both sides use the same key: one party signed everything.');
  const list = Array.isArray(record.messages) ? record.messages : [];
  out.messages = list.length;

  // 1. Signatures and senders.
  const good: { index: number; m: Obj; sig: string; seq?: number }[] = [];
  for (const [index, entry] of list.entries()) {
    const m = isObj(entry) ? entry.message : undefined;
    const sig = isObj(entry) ? entry.signature : undefined;
    const type = isObj(m) && typeof m.type === 'string' ? m.type : '(none)';
    const reject = (reason: string) => out.rejected.push({ index, type, reason });
    if (!isObj(m) || (m.from !== 'issuer' && m.from !== 'licensee')) {
      reject('names no sender');
      continue;
    }
    if (!Number.isSafeInteger(m.at)) {
      reject('has no signed time');
      continue;
    }
    if (!(await verifyEd25519(dealMessagePayload(m), sig, keys[m.from]))) {
      reject(`signature does not verify under the ${m.from}'s key`);
      continue;
    }
    out.verified++;
    const sender = SENDER[type];
    if (!sender) {
      // Signed and verified, but a kind this version doesn't read: noted, not a failure, so a
      // newer app's record still checks with an older tool.
      out.unread.push({ index, type });
      continue;
    }
    if (sender !== 'either' && sender !== m.from) {
      reject(`a ${type} comes from the ${sender}, this one from the ${m.from}`);
      continue;
    }
    const seq = isObj(entry) && Number.isSafeInteger(entry.seq) && (entry.seq as number) > 0 ? (entry.seq as number) : undefined;
    good.push({ index, m, sig: sig as string, seq });
  }

  // 2. Statements, then what answers them, in the registry's order when every message carries
  // a distinct seq; otherwise by signed time (the sender's own clock), and the result says so.
  const seqs = good.map((g) => g.seq);
  const bySeq = good.length > 0 && seqs.every((x) => x !== undefined) && new Set(seqs).size === seqs.length;
  out.order = bySeq ? 'registry' : 'signed-time';
  good.sort((a, b) =>
    bySeq ? a.seq! - b.seq! : (a.m.at as number) - (b.m.at as number) || a.index - b.index,
  );
  const bySig = new Map<string, DealStatementLine>();
  for (const { index, m, sig } of good) {
    if (m.type !== 'statement') continue;
    if (!text(m.statementId, 100) || !day(m.periodFrom) || !day(m.periodTo) || !dec(m.amountOwed) || !text(m.currency, 10)) {
      out.rejected.push({ index, type: 'statement', reason: 'malformed statement' });
      continue;
    }
    const line: DealStatementLine = {
      statementId: m.statementId,
      periodFrom: m.periodFrom,
      periodTo: m.periodTo,
      amountOwed: m.amountOwed,
      currency: m.currency,
      signature: sig,
      ...(dec(m.taxWithheld) ? { taxWithheld: m.taxWithheld } : {}),
      settled: false,
      notes: [],
    };
    bySig.set(sig, line);
    out.statements.push(line);
  }
  // Replies first, then payments, then confirmations, each in that order, as the web app reads
  // them: the first reply stands; a payment counts only on an accepted statement; a
  // confirmation only on a payment.
  for (const pass of ['reply', 'paid', 'received'] as const)
    for (const { index, m } of good) {
      if (m.type !== pass) continue;
      const line = typeof m.statementSig === 'string' ? bySig.get(m.statementSig) : undefined;
      if (!line) {
        out.rejected.push({ index, type: pass, reason: 'names no statement in this record' });
        continue;
      }
      if (m.type === 'reply') {
        if (m.decision !== 'accepted' && m.decision !== 'disputed') {
          out.rejected.push({ index, type: 'reply', reason: 'malformed reply' });
        } else if (line.reply) line.notes.push(`a later reply (${m.decision}) is ignored: the first one stands`);
        else line.reply = m.decision;
      } else if (m.type === 'paid') {
        if (!dec(m.amount) || !text(m.currency, 10) || !text(m.method, 80) || !text(m.reference, 120) || !day(m.paidOn)) {
          out.rejected.push({ index, type: 'paid', reason: 'malformed payment' });
        } else if (line.reply !== 'accepted') line.notes.push('a "paid" for a statement not accepted is ignored');
        else if (line.paid) line.notes.push('a second "paid" for this statement is ignored');
        else {
          line.paid = { amount: m.amount, currency: m.currency, method: m.method, reference: m.reference, paidOn: m.paidOn };
          const owed = toPay(line);
          if (m.currency !== line.currency) {
            line.short = owed;
            line.notes.push(`paid in ${m.currency}, but the statement is in ${line.currency}: ${owed} ${line.currency} still owed`);
          } else if (sub(owed, m.amount) > 0n) {
            line.short = fromUnits(sub(owed, m.amount));
            line.notes.push(`short payment: paid ${m.amount} of ${owed} ${line.currency}, ${line.short} still owed`);
          }
        }
      } else {
        if (!dec(m.amount) || !text(m.currency, 10)) {
          out.rejected.push({ index, type: 'received', reason: 'malformed confirmation' });
        } else if (line.received) line.notes.push('a second "received" for this statement is ignored');
        else line.received = { amount: m.amount, currency: m.currency };
      }
    }

  // 3. Settled: the same money signed for by both sides.
  const settled = new Map<string, bigint>();
  const open = new Map<string, bigint>();
  for (const line of out.statements) {
    const { paid, received } = line;
    if (paid && received) {
      if (paid.currency !== received.currency || !sameAmount(paid.amount, received.amount)) {
        line.notes.push(
          `paid ${paid.amount} ${paid.currency} but confirmed ${received.amount} ${received.currency}: not counted`,
        );
      } else if (line.short !== undefined) {
        line.notes.push('the payment confirmed was short of what the statement owes: not settled');
      } else {
        line.settled = true;
        add(settled, received.currency, received.amount);
      }
    } else if (received && !paid) line.notes.push('confirmed received, but the licensee never signed a payment: not counted');
    if (!line.settled && line.reply === 'accepted') add(open, line.currency, line.short ?? toPay(line));
  }
  out.settled = asRecord(settled);
  out.open = asRecord(open);
  return out;
};
