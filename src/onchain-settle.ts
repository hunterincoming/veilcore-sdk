// Settled on chain (SPEC 11.10): a royalty statement paid in a dollar stablecoin on Cardano,
// from the licensee's own wallet straight to the address the licensor signed, counts as paid
// and settled once the payment is found on Cardano. No signed "received" is needed: the licensor
// already signed both the address and the amount they accepted, and the transaction matches
// both.
//
// The link between the payment and the statement is a reference the transaction carries in
// its CIP-20 message (metadata label 674): "vc1:" and 32 hex characters of SHA-256 over the
// statement's signature and the payout address. Only someone holding the deal record can work
// it out; on the chain it names nothing.
//
// This module has no network code. A reader that wants to check payments gives
// checkDealRecord a lookup that answers for a transaction hash (from Blockfrost, Koios, its own
// node...): see `CardanoTx` for the shape.
//
// SPDX-License-Identifier: Apache-2.0

export const PAY_REF_DOMAIN = 'veilcore/pay-ref/v1\n';

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/**
 * The payment reference for a statement paid to an address: "vc1:" and the first 16 bytes of
 * SHA-256(UTF-8("veilcore/pay-ref/v1\n" + statementSig + "\n" + payTo)), lowercase hex.
 */
export const paymentReference = async (statementSig: string, payTo: string): Promise<string> => {
  const bytes = new TextEncoder().encode(`${PAY_REF_DOMAIN}${statementSig}\n${payTo.trim()}`);
  const subtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
  if (!subtle) throw new Error('paymentReference needs WebCrypto (globalThis.crypto.subtle)');
  return 'vc1:' + toHex(new Uint8Array(await subtle.digest('SHA-256', bytes))).slice(0, 32);
};

/** A token a statement can be paid in on Cardano at 1:1. */
export type CardanoToken = {
  /** What a payout and a payment name it: method `cardano:<code>`. */
  readonly code: string;
  /** The currency it pays at par. */
  readonly pays: string;
  readonly network: 'mainnet' | 'preprod' | 'preview';
  readonly policyId: string;
  readonly assetName: string;
  /** Base units per whole token, as a power of ten. */
  readonly decimals: number;
};

/**
 * The tokens the SPEC names (11.10, "Settled on chain"), on Cardano mainnet. A reader may give
 * others (a test token on preprod); a payment in a token the reader doesn't know is not checked.
 */
export const CARDANO_TOKENS: readonly CardanoToken[] = [
  {
    code: 'USDCx',
    pays: 'USD',
    network: 'mainnet',
    policyId: '1f3aec8bfe7ea4fe14c5f121e2a92e301afe414147860d557cac7e34',
    assetName: '5553444378',
    decimals: 6,
  },
  {
    code: 'USDM',
    pays: 'USD',
    network: 'mainnet',
    policyId: 'c48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7ac39fb402da47ad',
    assetName: '0014df105553444d',
    decimals: 6,
  },
];

/** A Cardano transaction, as much of it as the rule reads. Quantities are decimal strings. */
export type CardanoTx = {
  readonly hash: string;
  /** False when its scripts failed (only collateral moved). */
  readonly valid: boolean;
  /** How many blocks deep it is: 1 when in the newest block, 0 when not in a block. */
  readonly confirmations: number;
  /** Its outputs: Bech32 address and amounts by unit ("lovelace", or policy id + asset name hex). */
  readonly outputs: readonly { readonly address: string; readonly amounts: readonly { unit: string; quantity: string }[] }[];
  /** The lines of its label-674 `msg`. */
  readonly msg: readonly string[];
};

/** How deep a payment must be before it counts, unless the reader asks for more. */
export const MIN_CONFIRMATIONS = 10;

export type CardanoVerdict =
  | { readonly ok: true; readonly paid: string }
  | {
      readonly ok: false;
      readonly why: 'unconfirmed' | 'failed' | 'no-ref' | 'many-refs' | 'wrong-ref' | 'none' | 'short';
      readonly paid?: string;
    };

/**
 * The rule: the transaction is valid and at least `minConfirmations` deep; its message carries
 * exactly one line starting "vc1:", and it is `ref`; its outputs to `payTo` in `unit` add up to
 * at least `want` base units. More than owed is paid; the extra is between the parties.
 */
export const cardanoVerdict = (
  tx: CardanoTx,
  p: { payTo: string; unit: string; want: bigint | string; ref: string; minConfirmations?: number },
): CardanoVerdict => {
  const want = BigInt(p.want);
  if (!tx.valid) return { ok: false, why: 'failed' };
  if (tx.confirmations < (p.minConfirmations ?? MIN_CONFIRMATIONS)) return { ok: false, why: 'unconfirmed' };
  const refs = tx.msg.filter((l) => typeof l === 'string' && l.startsWith('vc1:'));
  if (refs.length === 0) return { ok: false, why: 'no-ref' };
  if (refs.length > 1) return { ok: false, why: 'many-refs' };
  if (refs[0] !== p.ref) return { ok: false, why: 'wrong-ref' };
  let paid = 0n;
  for (const o of tx.outputs) {
    if (o.address !== p.payTo.trim()) continue;
    for (const a of o.amounts) if (a.unit === p.unit && /^\d{1,40}$/.test(a.quantity)) paid += BigInt(a.quantity);
  }
  if (paid === 0n) return { ok: false, why: 'none' };
  if (paid < want) return { ok: false, why: 'short', paid: String(paid) };
  return { ok: true, paid: String(paid) };
};

/** A decimal amount in a token's base units, exactly; undefined if it has more decimals than the token. */
export const toTokenUnits = (amount: string, decimals: number): bigint | undefined => {
  const m = /^(\d{1,30})(?:\.(\d+))?$/.exec(amount.trim());
  if (!m) return undefined;
  const frac = (m[2] ?? '').replace(/0+$/, '');
  if (frac.length > decimals) return undefined;
  return BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt((frac + '0'.repeat(decimals)).slice(0, decimals) || '0');
};
