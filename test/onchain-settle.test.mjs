// Settled on chain (SPEC 11.10): the payment reference, the rule a Cardano transaction must
// meet, and checkDealRecord settling a statement paid on Cardano without "received", only with
// a lookup the reader gives, only in full and only with this statement's reference.
// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { webcrypto as crypto } from 'node:crypto';
import { cardanoVerdict, checkDealRecord, dealMessagePayload, paymentReference, toTokenUnits, CARDANO_TOKENS } from 'veilcore-records';

const V = JSON.parse(await readFile(new URL('../conformance/onchain-settle-v1.json', import.meta.url), 'utf8'));
const copy = (x) => JSON.parse(JSON.stringify(x));

test('the payment reference is vc1: and 32 hex of SHA-256 over the signature and the address', async () => {
  for (const v of V.payRef) {
    const want = 'vc1:' + createHash('sha256').update(`veilcore/pay-ref/v1\n${v.statementSig}\n${v.payTo.trim()}`).digest('hex').slice(0, 32);
    assert.equal(await paymentReference(v.statementSig, v.payTo), want);
    assert.equal(v.ref, want);
  }
});

test('the rule, case by case', () => {
  for (const c of V.verdicts) assert.deepEqual(cardanoVerdict(c.tx, c.expect), c.result, c.name);
});

test('a deal record paid on Cardano: settled only with a lookup, in full, with its own reference', async () => {
  for (const d of V.dealRecords) {
    const c = await checkDealRecord(d.record, d.chain ? { cardano: async (h) => d.chain[h] } : {});
    assert.deepEqual(c.rejected, [], d.name);
    assert.deepEqual(
      { statements: c.statements.map((l) => ({ statementId: l.statementId, settled: l.settled, onChain: l.onChain?.result ?? null })), settled: c.settled, open: c.open },
      d.result,
      d.name,
    );
  }
});

// The fixed keys the vectors were signed with (RFC 8032 tests 1 and 2), to sign changed copies.
const KEYS = {
  issuer: ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'],
  licensee: ['4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'],
};
const b64u = (h) => Buffer.from(h, 'hex').toString('base64url');
const signAs = async (who, m) => {
  const [d, x] = KEYS[who];
  const key = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', d: b64u(d), x: b64u(x) }, 'Ed25519', false, ['sign']);
  return Buffer.from(await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(dealMessagePayload(m)))).toString('hex');
};
/** The record with its payout changed and signed again, and the payments naming the new payout. */
const withPayout = async (record, change) => {
  const r = copy(record);
  const p = r.messages[0];
  change(p.message);
  p.signature = await signAs('issuer', p.message);
  for (const e of r.messages)
    if (e.message.type === 'paid') {
      e.message.payoutSig = p.signature;
      e.signature = await signAs('licensee', e.message);
    }
  return r;
};

test('the payout must say 1:1, in the statement’s currency, and the token must pay that currency', async () => {
  const d = V.dealRecords[0];
  const lookup = async (h) => d.chain[h];
  const same = await checkDealRecord(await withPayout(d.record, () => {}), { cardano: lookup });
  assert.equal(same.statements[0].settled, true, 'signed again unchanged: still settled');
  for (const [what, change] of [
    ['no rate', (m) => { delete m.rate; }],
    ['rate 1.01', (m) => { m.rate = '1.01'; }],
    ['payout in EUR', (m) => { m.currency = 'EUR'; }],
    ['another token', (m) => { m.method = 'cardano:USDM'; }],
  ]) {
    const c = await checkDealRecord(await withPayout(d.record, change), { cardano: lookup });
    assert.deepEqual(c.rejected, [], what);
    assert.equal(c.statements[0].settled, false, what);
    assert.equal(c.statements[0].onChain, undefined, what);
  }
});

test('a lookup that fails, or answers for another transaction, settles nothing', async () => {
  const d = V.dealRecords[0];
  const failing = await checkDealRecord(d.record, { cardano: async () => { throw new Error('down'); } });
  assert.equal(failing.statements[0].onChain.result, 'not-found');
  const lying = await checkDealRecord(d.record, { cardano: async () => ({ ...d.chain[Object.keys(d.chain)[0]], hash: 'ff'.repeat(32) }) });
  assert.equal(lying.statements[0].settled, false);
  assert.deepEqual(lying.settled, {});
});

test('a deeper threshold is the reader’s choice', async () => {
  const d = V.dealRecords[0];
  const c = await checkDealRecord(d.record, { cardano: async (h) => d.chain[h], minConfirmations: 100 });
  assert.equal(c.statements[0].onChain.result, 'unconfirmed');
});

test('tokens: USDCx and USDM on mainnet, six decimals; amounts in base units exactly', () => {
  assert.deepEqual(CARDANO_TOKENS.map((t) => [t.code, t.pays, t.network, t.decimals]), [['USDCx', 'USD', 'mainnet', 6], ['USDM', 'USD', 'mainnet', 6]]);
  assert.equal(toTokenUnits('900.00', 6), 900000000n);
  assert.equal(toTokenUnits('0.0000001', 6), undefined);
  assert.equal(toTokenUnits('12abc', 6), undefined);
});
