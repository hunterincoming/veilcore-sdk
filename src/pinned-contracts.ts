// Several contracts (SPEC 9.4): which of VeilCore's anchoring contracts a check reads.
//
// A verifier holds its own pinned list of contracts, per network. A contract is identified
// only by its address on that list: never by a version or `predecessor` field in the
// contract's own state, a record or a registry answer. A transaction is read by the one pinned
// contract it calls. The same commitment on two contracts is two records with two dates, never
// joined. Off mainnet, a check names its contract version; a defaulted version fails.
//
// This module has no network code and holds no list of its own: the caller passes the list it
// pins, so a checker can't pick up a contract from anywhere else.
//
// SPDX-License-Identifier: Apache-2.0

/** One contract on a verifier's pinned list. */
export type PinnedContract = {
  readonly network: string;
  /** 64 lowercase hex characters. */
  readonly address: string;
  readonly kind: 'main' | 'claims';
  /** The contract version, as the list gives it. */
  readonly version: number;
  /** What every date from this contract is shown with. */
  readonly name: string;
};

/** What a contract's own state says about itself. Never used to identify it (SPEC 9.4 (2)). */
export type StatedContractFields = {
  readonly contractVersion?: unknown;
  readonly predecessor?: unknown;
};

export type ContractRefusal =
  | 'malformed-address'
  | 'not-pinned'
  | 'version-not-named'
  | 'version-mismatch'
  | 'no-pinned-contract'
  | 'several-pinned-contracts'
  | 'named-contract-not-called';

export type ContractChoice =
  | { readonly ok: true; readonly contracts: PinnedContract[] }
  | { readonly ok: false; readonly refused: ContractRefusal };

const HEX64 = /^[0-9a-f]{64}$/;

const checkList = (list: readonly PinnedContract[]): void => {
  if (!Array.isArray(list)) throw new TypeError('pinned list must be an array');
  const seen = new Set<string>();
  for (const c of list) {
    if (typeof c !== 'object' || c === null) throw new TypeError('pinned list: an entry is not an object');
    if (typeof c.network !== 'string' || !c.network) throw new TypeError('pinned list: an entry has no network');
    if (typeof c.address !== 'string' || !HEX64.test(c.address)) throw new TypeError(`pinned list: ${String(c.address)} is not 64 lowercase hex`);
    if (c.kind !== 'main' && c.kind !== 'claims') throw new TypeError(`pinned list: ${c.address} has kind ${String(c.kind)}`);
    if (!Number.isSafeInteger(c.version) || c.version < 1) throw new TypeError(`pinned list: ${c.address} has version ${String(c.version)}`);
    if (typeof c.name !== 'string' || !c.name.trim()) throw new TypeError(`pinned list: ${c.address} has no name`);
    const key = `${c.network}\n${c.address}`;
    if (seen.has(key)) throw new TypeError(`pinned list: ${c.address} is listed twice on ${c.network}`);
    seen.add(key);
  }
};

/** Off mainnet the version is named by the check itself; on mainnet it may be. */
const versionProblem = (network: string, version: unknown): ContractRefusal | null => {
  if (version === undefined || version === null) return network === 'mainnet' ? null : 'version-not-named';
  return Number.isSafeInteger(version) && (version as number) >= 1 ? null : 'version-not-named';
};

const refuse = (refused: ContractRefusal): ContractChoice => ({ ok: false, refused });

/**
 * The pinned contracts a check reads (SPEC 9.4 (1), (2) and (5)).
 *
 * With an address: that contract, only if it is on the list for this network. Without one: every
 * pinned contract on the network (of the named version, if one is named), never a default one.
 * `stated` is what the contract's own state says about itself; it is accepted so that a caller
 * can pass it, and deliberately never read.
 */
export const pinnedContracts = (
  list: readonly PinnedContract[],
  query: { network: string; address?: string; version?: number; stated?: StatedContractFields },
): ContractChoice => {
  checkList(list);
  const { network, address, version } = query;
  const v = versionProblem(network, version);
  if (v) return refuse(v);
  if (address !== undefined) {
    if (typeof address !== 'string' || !HEX64.test(address)) return refuse('malformed-address');
    const entry = list.find((c) => c.network === network && c.address === address);
    if (!entry) return refuse('not-pinned');
    if (version !== undefined && version !== null && entry.version !== version) return refuse('version-mismatch');
    return { ok: true, contracts: [entry] };
  }
  const all = list.filter((c) => c.network === network && (version === undefined || version === null || c.version === version));
  return all.length ? { ok: true, contracts: all } : refuse('no-pinned-contract');
};

/**
 * The one pinned contract a transaction is decoded by (SPEC 9.4 (1) and (3)): the pinned
 * contract it calls. A transaction that calls none, or more than one, is refused. Calls to
 * contracts that are not pinned don't count either way, but every address in `calls` must be
 * 64 lowercase hex: one written any other way is refused, never normalised, so that letter case
 * can't hide a second pinned contract.
 *
 * `named` is the address the record names (`anchor.contractAddress` or
 * `ledgerIdentity.contractAddress`), if it names one: the transaction must call that contract.
 */
export const contractForTransaction = (
  list: readonly PinnedContract[],
  query: { network: string; calls: readonly string[]; version?: number; named?: string },
): ContractChoice => {
  checkList(list);
  const { network, calls, version, named } = query;
  const v = versionProblem(network, version);
  if (v) return refuse(v);
  if (!Array.isArray(calls)) throw new TypeError('calls must be an array of contract addresses');
  if (calls.some((a) => typeof a !== 'string' || !HEX64.test(a))) return refuse('malformed-address');
  if (named !== undefined) {
    const n = pinnedContracts(list, { network, address: named, version });
    if (!n.ok) return n;
  }
  const called = list.filter((c) => c.network === network && calls.includes(c.address));
  if (called.length === 0) return refuse('no-pinned-contract');
  if (called.length > 1) return refuse('several-pinned-contracts');
  if (version !== undefined && version !== null && called[0].version !== version) return refuse('version-mismatch');
  if (named !== undefined && called[0].address !== named) return refuse('named-contract-not-called');
  return { ok: true, contracts: called };
};

/** Where a commitment was found on the ledger, as a lookup reports it. */
export type CommitmentSighting = {
  readonly address: string;
  readonly commitment: string;
  /** The date the anchoring transaction gives, RFC 3339. */
  readonly date: string;
};

export type DatedRecord = {
  readonly commitment: string;
  readonly date: string;
  /** The pinned entry's name: every date is shown with it. */
  readonly contract: string;
  readonly address: string;
  readonly version: number;
};

/**
 * Dates for commitments found on several contracts (SPEC 9.4 (4)). Each sighting on a pinned
 * contract is its own record with its own date and the name of the contract that gave it. The
 * same commitment on two contracts stays two records: nothing is merged, and no record takes
 * another's date. A sighting on a contract that is not pinned gives no date.
 */
export const datedRecords = (
  list: readonly PinnedContract[],
  query: { network: string; sightings: readonly CommitmentSighting[]; version?: number },
): { records: DatedRecord[]; refused: { address: string; commitment: string; refused: ContractRefusal }[] } => {
  checkList(list);
  const { network, sightings, version } = query;
  if (!Array.isArray(sightings)) throw new TypeError('sightings must be an array');
  const records: DatedRecord[] = [];
  const refused: { address: string; commitment: string; refused: ContractRefusal }[] = [];
  for (const s of sightings) {
    const choice = pinnedContracts(list, { network, address: s.address, version });
    if (!choice.ok) {
      refused.push({ address: s.address, commitment: s.commitment, refused: choice.refused });
      continue;
    }
    const c = choice.contracts[0];
    records.push({ commitment: s.commitment, date: s.date, contract: c.name, address: c.address, version: c.version });
  }
  return { records, refused };
};
