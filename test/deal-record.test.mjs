// Deal records (SPEC 11.10): checked against one the web app itself made
// (fixtures/deal-record-app.json, built with the app's deal.ts and deal-client.ts), then
// against records altered or forged the ways a borrower showing a lender might.
// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { webcrypto as crypto } from 'node:crypto';
import { checkDealRecord, dealMessagePayload, sameAmount } from 'veilcore-records';

const APP = JSON.parse(await readFile(new URL('./fixtures/deal-record-app.json', import.meta.url), 'utf8'));
const BIN = new URL('../bin/veilcore.mjs', import.meta.url).pathname;
const copy = (x) => JSON.parse(JSON.stringify(x));
const hex = (b) => Buffer.from(b).toString('hex');

/** A deal key pair made with WebCrypto, and a signer for deal messages. */
const party = async () => {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = hex(await crypto.subtle.exportKey('raw', kp.publicKey));
  const sign = async (m) => hex(await crypto.subtle.sign('Ed25519', kp.privateKey, new TextEncoder().encode(dealMessagePayload(m))));
  return { pub, sign };
};
const recordOf = async (issuer, licensee, signed) => ({
  v: 'veilcore/deal-record/v1',
  license: { commitment: 'c3'.repeat(32), issuerRecord: 'd4'.repeat(32) },
  keys: { issuer: issuer.pub, licensee: licensee.pub },
  messages: await Promise.all(signed.map(async ([who, m]) => ({ message: m, signature: await who.sign(m) }))),
});
const at = (d) => Date.parse(`${d}T12:00:00Z`);
const statement = (id, owed, day) => ({
  type: 'statement', statementId: id, periodFrom: '2026-07-01', periodTo: '2026-07-31', basis: 'sales',
  quantity: '1', currency: 'USD', amountOwed: owed, from: 'licensee', at: at(day),
});

test('the app\'s own record: every signature verifies, and only what both signed is settled', async () => {
  const c = await checkDealRecord(APP);
  assert.equal(c.messages, 9);
  assert.equal(c.verified, 9);
  assert.deepEqual(c.rejected, []);
  assert.deepEqual(c.problems, []);
  assert.deepEqual(c.settled, { USD: '120.5' });
  assert.deepEqual(c.open, { USD: '80' });
  assert.deepEqual(c.statements.map((s) => [s.statementId, s.reply, s.settled]), [
    ['S-1', 'accepted', true],
    ['S-2', 'accepted', false],
    ['S-3', 'disputed', false],
  ]);
});

test('a changed amount no longer verifies, and stops counting', async () => {
  const r = copy(APP);
  const s = r.messages.find((e) => e.message.type === 'statement');
  s.message.amountOwed = '1205.00';
  const c = await checkDealRecord(r);
  assert.equal(c.verified, 8);
  assert.match(c.rejected[0].reason, /does not verify under the licensee's key/);
  // Its payment and confirmation now name no statement.
  assert.ok(c.rejected.some((x) => x.type === 'paid' && /names no statement/.test(x.reason)));
  assert.deepEqual(c.settled, {});
});

test('swapping the two keys breaks every signature', async () => {
  const r = copy(APP);
  r.keys = { issuer: APP.keys.licensee, licensee: APP.keys.issuer };
  const c = await checkDealRecord(r);
  assert.equal(c.verified, 0);
  assert.deepEqual(c.settled, {});
});

test('the licensor cannot sign the licensee\'s "paid" for them', async () => {
  const I = await party(), L = await party();
  const s = statement('S-1', '50', '2026-08-01');
  const r = await recordOf(I, L, [[L, s]]);
  const sig = r.messages[0].signature;
  const more = await recordOf(I, L, [
    [I, { type: 'paid', statementId: 'S-1', statementSig: sig, amount: '50', currency: 'USD', method: 'cash', payTo: 'x', reference: 'r', paidOn: '2026-08-02', from: 'issuer', at: at('2026-08-02') }],
    [I, { type: 'received', statementId: 'S-1', statementSig: sig, amount: '50', currency: 'USD', from: 'issuer', at: at('2026-08-03') }],
  ]);
  r.messages.push(...more.messages);
  const c = await checkDealRecord(r);
  assert.ok(c.rejected.some((x) => x.type === 'paid' && /comes from the licensee/.test(x.reason)));
  assert.deepEqual(c.settled, {});
  assert.match(c.statements[0].notes.join(' '), /never signed a payment/);
});

test('one key on both sides is named as a problem', async () => {
  const P = await party();
  const c = await checkDealRecord(await recordOf(P, P, [[P, statement('S-1', '50', '2026-08-01')]]));
  assert.match(c.problems.join(' '), /same key/);
});

test('a small-order key verifies nothing', async () => {
  const I = await party();
  const m = statement('S-1', '50', '2026-08-01');
  const r = {
    v: 'veilcore/deal-record/v1',
    keys: { issuer: I.pub, licensee: '01' + '00'.repeat(31) },
    // R = the identity point, S = 0: "valid" for any message under a lenient check.
    messages: [{ message: m, signature: '01' + '00'.repeat(63) }],
  };
  const c = await checkDealRecord(r);
  assert.equal(c.verified, 0);
});

test('paid and received for different amounts is not settled', async () => {
  const I = await party(), L = await party();
  const s = statement('S-1', '50', '2026-08-01');
  const r = await recordOf(I, L, [[L, s]]);
  const sig = r.messages[0].signature;
  const more = await recordOf(I, L, [
    [I, { type: 'reply', statementId: 'S-1', statementSig: sig, decision: 'accepted', from: 'issuer', at: at('2026-08-02') }],
    [L, { type: 'paid', statementId: 'S-1', statementSig: sig, amount: '50', currency: 'USD', method: 'cash', payTo: 'x', reference: 'r', paidOn: '2026-08-02', from: 'licensee', at: at('2026-08-03') }],
    [I, { type: 'received', statementId: 'S-1', statementSig: sig, amount: '40', currency: 'USD', from: 'issuer', at: at('2026-08-04') }],
  ]);
  r.messages.push(...more.messages);
  const c = await checkDealRecord(r);
  assert.deepEqual(c.settled, {});
  assert.deepEqual(c.open, { USD: '50' });
  assert.match(c.statements[0].notes.join(' '), /not counted/);
});

test('amounts compare as decimals, not as text', () => {
  assert.ok(sameAmount('10', '10.00'));
  assert.ok(sameAmount('0.1', '0.10'));
  assert.ok(!sameAmount('10', '10.01'));
  assert.ok(!sameAmount('1e1', '10'));
});

test('not a deal record: nothing verified, never an exception', async () => {
  for (const x of [null, 42, 'x', {}, { v: 'veilcore/deal-record/v1' }, { v: 'veilcore/deal-record/v1', keys: { issuer: 'zz', licensee: 'zz' } }]) {
    const c = await checkDealRecord(x);
    assert.equal(c.verified, 0);
    assert.equal(c.problems.length, 1);
  }
});

const run = (args) =>
  new Promise((resolve) => execFile(process.execPath, [BIN, ...args], (err, stdout) => resolve({ code: err ? err.code : 0, stdout })));

test('veilcore deal: a record file, and the deals inside a backup', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'veilcore-deal-'));
  const one = await run(['deal', new URL('./fixtures/deal-record-app.json', import.meta.url).pathname]);
  assert.equal(one.code, 0);
  assert.match(one.stdout, /9 of 9 signed/);
  assert.match(one.stdout, /settled \(both signed\)\s+120\.5 USD/);
  assert.match(one.stdout, /Confirm with the\s+licensee/);

  const backup = join(dir, 'backup.json');
  await writeFile(backup, JSON.stringify({ format: 'veilcore-backup', version: 3, dealRecords: [APP] }));
  const viaBackup = await run(['deal', backup]);
  assert.equal(viaBackup.code, 0);
  assert.match(viaBackup.stdout, /120\.5 USD/);

  const bad = copy(APP);
  bad.messages[1].message.amountOwed = '999';
  const badFile = join(dir, 'bad.json');
  await writeFile(badFile, JSON.stringify(bad));
  const no = await run(['deal', badFile]);
  assert.equal(no.code, 1);
  assert.match(no.stdout, /DOES NOT COUNT/);

  const empty = join(dir, 'empty.json');
  await writeFile(empty, JSON.stringify({ format: 'veilcore-backup', version: 3 }));
  assert.equal((await run(['deal', empty])).code, 1);
});

test('hand-on messages count from the right side; an unknown kind is unread, not a failure', async () => {
  const I = await party(), L = await party();
  const r = await recordOf(I, L, [
    [L, { type: 'handon-ask', to: 'Second Grower', from: 'licensee', at: at('2026-10-01') }],
    [I, { type: 'handon', newLicense: 'ab'.repeat(32), to: 'Second Grower', from: 'issuer', at: at('2026-10-02') }],
    [L, { type: 'handon', newLicense: 'cd'.repeat(32), to: 'Mallory', from: 'licensee', at: at('2026-10-03') }],
    [I, { type: 'something-newer', from: 'issuer', at: at('2026-10-04') }],
  ]);
  const c = await checkDealRecord(r);
  assert.equal(c.verified, 4);
  assert.deepEqual(c.rejected.map((x) => [x.type, /comes from the issuer/.test(x.reason)]), [['handon', true]]);
  assert.deepEqual(c.unread, [{ index: 3, type: 'something-newer' }]);
});
