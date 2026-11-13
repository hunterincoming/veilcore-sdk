// Vectors for "Settled on chain" (SPEC 11.10): onchain-settle-v1.json, next to this file.
//
//   npm run build && node conformance/onchain-settle-vectors.mjs
//
// Three parts, each computed by this package (dist/):
//   - payRef: the payment reference for a statement signature and a payout address;
//   - verdicts: whether a Cardano transaction pays a statement, case by case;
//   - dealRecords: whole deal records, signed with fixed keys, the transactions a Cardano lookup
//     answers for, and which statements come out settled. The web application checks the first
//     two with its own code (its copy lives in bboard-ui/src/veilcore/fixtures/).
// SPDX-License-Identifier: Apache-2.0

import { writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';
import { cardanoVerdict, checkDealRecord, dealMessagePayload, paymentReference, CARDANO_TOKENS } from '../dist/index.js';

const hex = (b) => Buffer.from(b).toString('hex');
const b64u = (h) => Buffer.from(h, 'hex').toString('base64url');

// Two fixed Ed25519 keys (RFC 8032 test 1 and 2 secrets), so the signatures never change.
const SECRETS = {
  issuer: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  licensee: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
};
const party = async (secret) => {
  const pubHex = {
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60': 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb': '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  }[secret];
  const key = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', d: b64u(secret), x: b64u(pubHex) }, 'Ed25519', false, ['sign']);
  return { pub: pubHex, sign: async (m) => hex(await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(dealMessagePayload(m)))) };
};

const LICENSOR = 'addr1qyzf75t34nj2gy8ujleuthj96x003mnzhl04vev0289wnmlk5v628yzh2f7vvzv3vqy4rjm6ntte397rr3j6r7ng3jjswyst58';
const ELSEWHERE = 'addr1q80qxm73qm3t982h5sqt0ltnjyd2nykfsvfuxv3ywq3uy5d4x7gt66hzqs36h8u3ggsysx0yq6yc4kqf6rpr6540f8pqjrgfdr';
const USDCX = CARDANO_TOKENS.find((t) => t.code === 'USDCx');
const UNIT = USDCX.policyId + USDCX.assetName;

// ---- payment references -------------------------------------------------------------------

const payRef = [];
for (const [statementSig, payTo] of [
  ['ab'.repeat(64), LICENSOR],
  ['ab'.repeat(64), ELSEWHERE],
  ['cd'.repeat(64), LICENSOR],
  ['0f'.repeat(64), `  ${LICENSOR}  `],
]) payRef.push({ statementSig, payTo, ref: await paymentReference(statementSig, payTo) });

// ---- verdicts -----------------------------------------------------------------------------

const REF = await paymentReference('ab'.repeat(64), LICENSOR);
const OTHER_REF = await paymentReference('cd'.repeat(64), LICENSOR);
const tx = (over = {}) => ({
  hash: 'c1'.repeat(32),
  valid: true,
  confirmations: 12,
  outputs: [
    { address: LICENSOR, amounts: [{ unit: 'lovelace', quantity: '1180000' }, { unit: UNIT, quantity: '900000000' }] },
    { address: ELSEWHERE, amounts: [{ unit: 'lovelace', quantity: '30000000' }] },
  ],
  msg: [REF],
  ...over,
});
const expectation = { payTo: LICENSOR, unit: UNIT, want: '900000000', ref: REF };
const cases = [
  ['exactly what is owed', tx(), expectation],
  ['more than owed', tx({ outputs: [{ address: LICENSOR, amounts: [{ unit: UNIT, quantity: '950000000' }] }] }), expectation],
  ['two outputs to the address add up', tx({ outputs: [
    { address: LICENSOR, amounts: [{ unit: UNIT, quantity: '400000000' }] },
    { address: LICENSOR, amounts: [{ unit: UNIT, quantity: '500000000' }] },
  ] }), expectation],
  ['one base unit short', tx({ outputs: [{ address: LICENSOR, amounts: [{ unit: UNIT, quantity: '899999999' }] }] }), expectation],
  ['paid to another address', tx({ outputs: [{ address: ELSEWHERE, amounts: [{ unit: UNIT, quantity: '900000000' }] }] }), expectation],
  ['another token', tx({ outputs: [{ address: LICENSOR, amounts: [{ unit: 'ff'.repeat(28) + USDCX.assetName, quantity: '900000000' }] }] }), expectation],
  ['another statement’s reference', tx({ msg: [OTHER_REF] }), expectation],
  ['two references', tx({ msg: [REF, OTHER_REF] }), expectation],
  ['no reference', tx({ msg: ['royalty Q1'] }), expectation],
  ['other lines beside the reference are fine', tx({ msg: ['royalty Q1', REF] }), expectation],
  ['failed scripts', tx({ valid: false }), expectation],
  ['9 blocks deep', tx({ confirmations: 9 }), expectation],
  ['10 blocks deep', tx({ confirmations: 10 }), expectation],
];
const verdicts = cases.map(([name, t, e]) => ({ name, tx: t, expect: e, result: cardanoVerdict(t, e) }));

// ---- whole deal records -------------------------------------------------------------------

const at = (d) => Date.parse(`${d}T12:00:00Z`);
const issuer = await party(SECRETS.issuer);
const licensee = await party(SECRETS.licensee);
const statement = (id, owed, extra = {}) => ({
  type: 'statement', statementId: id, periodFrom: '2026-07-01', periodTo: '2026-09-30', basis: 'units',
  quantity: '400', currency: 'USD', amountOwed: owed, from: 'licensee', at: at('2026-10-02'), ...extra,
});
const s1 = statement('S-1', '1000.00', { taxWithheld: '100.00' });
const s2 = statement('S-2', '250.00', { periodFrom: '2026-10-01', periodTo: '2026-12-31' });
const s3 = statement('S-3', '80.00', { periodFrom: '2027-01-01', periodTo: '2027-03-31' });
const payout = { type: 'payout', method: 'cardano:USDCx', account: LICENSOR, currency: 'USD', rate: '1', from: 'issuer', at: at('2026-10-01') };
const sig1 = await licensee.sign(s1);
const sig2 = await licensee.sign(s2);
const sig3 = await licensee.sign(s3);
const payoutSig = await issuer.sign(payout);
const reply = (sig, d) => ({ type: 'reply', statementId: 'x', statementSig: sig, decision: 'accepted', from: 'issuer', at: at(d) });
const paid = (sig, id, amount, txHash) => ({
  type: 'paid', statementId: id, statementSig: sig, amount, currency: 'USD', method: 'cardano:USDCx', payTo: '',
  reference: txHash, paidOn: '2026-10-20', payoutSig, from: 'licensee', at: at('2026-10-20'),
});
const T1 = 'a1'.repeat(32);
const T2 = 'a2'.repeat(32);
const T3 = 'a3'.repeat(32);
const signed = [
  [issuer, payout], [licensee, s1], [licensee, s2], [licensee, s3],
  [issuer, reply(sig1, '2026-10-05')], [issuer, reply(sig2, '2026-10-05')], [issuer, reply(sig3, '2026-10-05')],
  [licensee, paid(sig1, 'S-1', '900.00', T1)], [licensee, paid(sig2, 'S-2', '250.00', T2)], [licensee, paid(sig3, 'S-3', '80.00', T3)],
];
const record = {
  v: 'veilcore/deal-record/v1',
  license: { commitment: 'c3'.repeat(32), issuerRecord: 'd4'.repeat(32) },
  keys: { issuer: issuer.pub, licensee: licensee.pub },
  messages: await Promise.all(signed.map(async ([who, m], i) => ({ message: m, signature: await who.sign(m), seq: i + 1 }))),
};
const ref1 = await paymentReference(sig1, LICENSOR);
const ref2 = await paymentReference(sig2, LICENSOR);
const ref3 = await paymentReference(sig3, LICENSOR);
const chain = {
  // S-1: 900 USDCx (owed 1000 less 100 tax declared), its reference: settled without "received".
  [T1]: { hash: T1, valid: true, confirmations: 40, outputs: [{ address: LICENSOR, amounts: [{ unit: UNIT, quantity: '900000000' }] }], msg: [ref1] },
  // S-2: carries S-1's reference: not this statement's payment.
  [T2]: { hash: T2, valid: true, confirmations: 40, outputs: [{ address: LICENSOR, amounts: [{ unit: UNIT, quantity: '250000000' }] }], msg: [ref1] },
  // S-3: its reference, 79.99: short.
  [T3]: { hash: T3, valid: true, confirmations: 40, outputs: [{ address: LICENSOR, amounts: [{ unit: UNIT, quantity: '79990000' }] }], msg: [ref3] },
};
void ref2;
const lookup = async (h) => chain[h];
const checked = await checkDealRecord(record, { cardano: lookup });
const unchecked = await checkDealRecord(record);
const summary = (c) => ({
  statements: c.statements.map((l) => ({ statementId: l.statementId, settled: l.settled, onChain: l.onChain?.result ?? null })),
  settled: c.settled,
  open: c.open,
});
const dealRecords = [
  { name: 'paid on Cardano: settled, wrong reference, short', record, chain, result: summary(checked) },
  { name: 'the same record with no Cardano lookup: nothing settled on chain', record, chain: null, result: summary(unchecked) },
];

const out = {
  v: 'veilcore/onchain-settle-vectors/v1',
  note: 'SPEC 11.10, "Settled on chain". Generated by conformance/onchain-settle-vectors.mjs from this package.',
  minConfirmations: 10,
  payRef,
  verdicts,
  dealRecords,
};
writeFileSync(new URL('./onchain-settle-v1.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`onchain-settle-v1.json: ${payRef.length} references, ${verdicts.length} verdicts, ${dealRecords.length} deal records`);
