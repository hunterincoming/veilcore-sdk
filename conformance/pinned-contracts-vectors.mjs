// Vectors for "Several contracts" (SPEC 9.4): pinned-contracts-v1.json, next to this file.
//
//   npm run build && node conformance/pinned-contracts-vectors.mjs
//
// A two-contract fixture: a version 1 and a version 2 main contract, plus a version 1 claims
// contract, on mainnet and on preprod. The addresses are made up for the fixture and are no
// real contract's. Three parts, each computed by this package (dist/):
//   - choices: which pinned contracts a check reads, given a network, an address or none, a
//     named version or none, and what the contract's own state says about itself (never read);
//   - transactions: the one pinned contract a transaction is decoded by;
//   - dates: the same commitment found on both contracts, and on one that is not pinned.
// SPDX-License-Identifier: Apache-2.0

import { writeFileSync } from 'node:fs';
import { pinnedContracts, contractForTransaction, datedRecords } from '../dist/index.js';

const A = (byte) => byte.repeat(32);
const V1 = A('11');
const V1_CLAIMS = A('12');
const V2 = A('21');
const V2_UNPINNED = A('2f');
const PRE_V1 = A('a1');
const PRE_V2 = A('a2');

const v1Only = [
  { network: 'mainnet', address: V1, kind: 'main', version: 1, name: 'VeilCore main contract v1' },
  { network: 'mainnet', address: V1_CLAIMS, kind: 'claims', version: 1, name: 'VeilCore claims contract v1' },
  { network: 'preprod', address: PRE_V1, kind: 'main', version: 1, name: 'VeilCore main contract v1 (preprod)' },
];
const twoContracts = [
  ...v1Only,
  { network: 'mainnet', address: V2, kind: 'main', version: 2, name: 'VeilCore main contract v2' },
  { network: 'preprod', address: PRE_V2, kind: 'main', version: 2, name: 'VeilCore main contract v2 (preprod)' },
];
const lists = { v1Only, twoContracts };

const names = (r) => (r.ok ? { ok: true, contracts: r.contracts.map((c) => c.address) } : r);

// ---- choices --------------------------------------------------------------------------------

const choices = [];
const choice = (name, list, query) => choices.push({ name, list, query, result: names(pinnedContracts(lists[list], query)) });

choice('a pinned v1 address on mainnet', 'twoContracts', { network: 'mainnet', address: V1 });
choice('a pinned v2 address on mainnet', 'twoContracts', { network: 'mainnet', address: V2 });
choice('a v2 address a v1-only list does not pin, though its state names the pinned v1 as predecessor', 'v1Only',
  { network: 'mainnet', address: V2, stated: { contractVersion: 2, predecessor: V1 } });
choice('an address on no list, whose state says it is version 2 with v1 as predecessor', 'twoContracts',
  { network: 'mainnet', address: V2_UNPINNED, stated: { contractVersion: 2, predecessor: V1 } });
choice('an address on no list, whose state says it is version 1', 'twoContracts',
  { network: 'mainnet', address: V2_UNPINNED, stated: { contractVersion: 1 } });
choice('a pinned v1 address whose state says version 2: read as v1, the field is not read', 'twoContracts',
  { network: 'mainnet', address: V1, stated: { contractVersion: 2, predecessor: V2 } });
choice('a pinned v2 address whose state says version 1: read as v2', 'twoContracts',
  { network: 'mainnet', address: V2, stated: { contractVersion: 1 } });
choice('a mainnet address checked as preprod', 'twoContracts', { network: 'preprod', address: V2, version: 2 });
choice('the right address with the wrong named version', 'twoContracts', { network: 'mainnet', address: V2, version: 1 });
choice('an address in capitals', 'twoContracts', { network: 'preprod', address: PRE_V2.toUpperCase(), version: 2 });
choice('an address one character short', 'twoContracts', { network: 'mainnet', address: V2.slice(1) });
choice('no address on mainnet: every pinned contract, no default', 'twoContracts', { network: 'mainnet' });
choice('no address on mainnet, version 2 named', 'twoContracts', { network: 'mainnet', version: 2 });
choice('no address on mainnet, version 3 named', 'twoContracts', { network: 'mainnet', version: 3 });
choice('preprod v2 with the version named', 'twoContracts', { network: 'preprod', address: PRE_V2, version: 2 });
choice('preprod v2 with no version named: a defaulted version fails', 'twoContracts', { network: 'preprod', address: PRE_V2 });
choice('preprod with no address and no version', 'twoContracts', { network: 'preprod' });
choice('preprod with no address, version 1 named', 'twoContracts', { network: 'preprod', version: 1 });
choice('preprod v2 named as version 1', 'twoContracts', { network: 'preprod', address: PRE_V2, version: 1 });
choice('preview, not on the list', 'twoContracts', { network: 'preview', address: PRE_V2, version: 2 });

// ---- transactions ---------------------------------------------------------------------------

const transactions = [];
const tx = (name, list, query) => transactions.push({ name, list, query, result: names(contractForTransaction(lists[list], query)) });

tx('calls v1 only: decoded as v1', 'twoContracts', { network: 'mainnet', calls: [V1] });
tx('calls v2 only: decoded as v2', 'twoContracts', { network: 'mainnet', calls: [V2] });
tx('calls v1 and v2: refused', 'twoContracts', { network: 'mainnet', calls: [V1, V2] });
tx('calls the v1 main and the v1 claims contracts: refused', 'twoContracts', { network: 'mainnet', calls: [V1, V1_CLAIMS] });
tx('calls v2 and a contract that is not pinned: decoded as v2', 'twoContracts', { network: 'mainnet', calls: [V2, V2_UNPINNED] });
tx('calls only a contract that is not pinned: refused', 'twoContracts', { network: 'mainnet', calls: [V2_UNPINNED] });
tx('calls v2, with a list that pins v1 only: refused', 'v1Only', { network: 'mainnet', calls: [V2] });
tx('calls v1 twice: one contract', 'twoContracts', { network: 'mainnet', calls: [V1, V1] });
tx('preprod v2 with the version named', 'twoContracts', { network: 'preprod', calls: [PRE_V2], version: 2 });
tx('preprod v2 with no version named', 'twoContracts', { network: 'preprod', calls: [PRE_V2] });
tx('preprod v2 named as version 1', 'twoContracts', { network: 'preprod', calls: [PRE_V2], version: 1 });

// ---- dates ----------------------------------------------------------------------------------

const C = 'c0'.repeat(32);
const D = 'd0'.repeat(32);
const sightings = [
  { address: V1, commitment: C, date: '2026-10-20T14:03:11Z' },
  { address: V2, commitment: C, date: '2026-12-02T09:41:57Z' },
  { address: V2_UNPINNED, commitment: C, date: '2026-09-01T00:00:00Z' },
  { address: V2, commitment: D, date: '2026-12-03T10:00:00Z' },
];
const dates = [];
const dated = (name, list, query) => dates.push({ name, list, query, result: datedRecords(lists[list], query) });

dated('the same commitment on v1 and v2: two records, two dates, each with its contract; an earlier sighting on an unpinned contract gives no date',
  'twoContracts', { network: 'mainnet', sightings });
dated('the same sightings with a list that pins v1 only: the v2 sightings give no date', 'v1Only', { network: 'mainnet', sightings });
dated('the same commitment on both preprod contracts, version 2 named: only v2 dates it', 'twoContracts', {
  network: 'preprod',
  version: 2,
  sightings: [
    { address: PRE_V1, commitment: C, date: '2026-11-25T08:00:00Z' },
    { address: PRE_V2, commitment: C, date: '2026-11-27T08:00:00Z' },
  ],
});
dated('preprod with no version named: nothing is dated', 'twoContracts', {
  network: 'preprod',
  sightings: [{ address: PRE_V2, commitment: C, date: '2026-11-27T08:00:00Z' }],
});

const out = {
  v: 'veilcore/pinned-contracts-vectors/v1',
  note: 'SPEC 9.4, "Several contracts". Generated by conformance/pinned-contracts-vectors.mjs from this package. Every address is made up for the fixture.',
  lists,
  choices,
  transactions,
  dates,
};
writeFileSync(new URL('./pinned-contracts-v1.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`pinned-contracts-v1.json: ${choices.length} choices, ${transactions.length} transactions, ${dates.length} date sets`);
