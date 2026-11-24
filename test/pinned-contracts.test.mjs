// Several contracts (SPEC 9.4): a contract is identified only by its pinned address, a
// transaction is decoded by the one pinned contract it calls, the same commitment on two
// contracts is two records with two dates, and off mainnet a check names its version.
// The expectations here are written out by hand, not read back from the vectors.
// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pinnedContracts, contractForTransaction, datedRecords } from 'veilcore-records';

const V = JSON.parse(await readFile(new URL('../conformance/pinned-contracts-v1.json', import.meta.url), 'utf8'));
const { twoContracts, v1Only } = V.lists;
const V1 = '11'.repeat(32);
const V2 = '21'.repeat(32);
const UNPINNED = '2f'.repeat(32);
const PRE_V2 = 'a2'.repeat(32);

test('the vectors still come out of this package', () => {
  const addr = (r) => (r.ok ? { ok: true, contracts: r.contracts.map((c) => c.address) } : r);
  for (const v of V.choices) assert.deepEqual(addr(pinnedContracts(V.lists[v.list], v.query)), v.result, v.name);
  for (const v of V.transactions) assert.deepEqual(addr(contractForTransaction(V.lists[v.list], v.query)), v.result, v.name);
  for (const v of V.dates) assert.deepEqual(datedRecords(V.lists[v.list], v.query), v.result, v.name);
});

test('the version and predecessor a contract states about itself are never read', () => {
  for (const stated of [undefined, {}, { contractVersion: 1 }, { contractVersion: 2 }, { contractVersion: 2, predecessor: V1 }, { predecessor: V2 }, { contractVersion: 'x' }]) {
    assert.equal(pinnedContracts(twoContracts, { network: 'mainnet', address: V1, stated }).contracts[0].version, 1);
    assert.equal(pinnedContracts(twoContracts, { network: 'mainnet', address: V2, stated }).contracts[0].version, 2);
    assert.deepEqual(pinnedContracts(twoContracts, { network: 'mainnet', address: UNPINNED, stated }), { ok: false, refused: 'not-pinned' });
    assert.deepEqual(pinnedContracts(v1Only, { network: 'mainnet', address: V2, stated }), { ok: false, refused: 'not-pinned' });
  }
});

test('the same commitment on v1 and v2 is two records: neither takes the other’s date', () => {
  const C = 'c0'.repeat(32);
  const r = datedRecords(twoContracts, {
    network: 'mainnet',
    sightings: [
      { address: V2, commitment: C, date: '2026-12-02T00:00:00Z' },
      { address: V1, commitment: C, date: '2026-10-01T00:00:00Z' },
    ],
  });
  assert.equal(r.records.length, 2);
  assert.deepEqual(r.records.map((x) => [x.contract, x.date]), [
    ['VeilCore main contract v2', '2026-12-02T00:00:00Z'],
    ['VeilCore main contract v1', '2026-10-01T00:00:00Z'],
  ]);
});

test('no default contract, and off mainnet a defaulted version fails', () => {
  assert.equal(pinnedContracts(twoContracts, { network: 'mainnet' }).contracts.length, 3);
  for (const network of ['preprod', 'preview', 'undeployed']) {
    assert.deepEqual(pinnedContracts(twoContracts, { network, address: PRE_V2 }), { ok: false, refused: 'version-not-named' }, network);
    assert.deepEqual(contractForTransaction(twoContracts, { network, calls: [PRE_V2] }), { ok: false, refused: 'version-not-named' }, network);
  }
  assert.deepEqual(pinnedContracts(twoContracts, { network: 'preprod', address: PRE_V2, version: 0 }), { ok: false, refused: 'version-not-named' });
  assert.equal(pinnedContracts(twoContracts, { network: 'preprod', address: PRE_V2, version: 2 }).ok, true);
});

test('a transaction calling two pinned contracts is refused, whatever order', () => {
  assert.deepEqual(contractForTransaction(twoContracts, { network: 'mainnet', calls: [V2, V1] }), { ok: false, refused: 'several-pinned-contracts' });
  assert.deepEqual(contractForTransaction(twoContracts, { network: 'mainnet', calls: [UNPINNED, V1] }).contracts.map((c) => c.address), [V1]);
});

test('a malformed pinned list is a programming error, not a refusal', () => {
  const one = twoContracts[0];
  for (const [what, list] of [
    ['not an array', null],
    ['capital address', [{ ...one, address: one.address.toUpperCase().replace(/1/g, 'A') }]],
    ['no version', [{ ...one, version: undefined }]],
    ['version 0', [{ ...one, version: 0 }]],
    ['unknown kind', [{ ...one, kind: 'router' }]],
    ['no name', [{ ...one, name: ' ' }]],
    ['listed twice', [one, { ...one }]],
  ]) assert.throws(() => pinnedContracts(list, { network: 'mainnet', address: V1 }), TypeError, what);
  // The same address on two networks is two entries, not a duplicate.
  assert.equal(pinnedContracts([one, { ...one, network: 'preprod' }], { network: 'mainnet', address: one.address }).ok, true);
});
