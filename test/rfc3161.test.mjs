// RFC 3161 timestamp tokens, checked offline with WebCrypto.
//
// Fixtures are real tokens made by `openssl ts` (test/fixtures/rfc3161/generate.sh) with
// TEST-ONLY keys. Each positive token was also verified by `openssl ts -verify` when it
// was generated, so these tests compare this parser with an independent implementation.
// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  verifyTimestampToken, timestampTokenBytes, TIMESTAMP_NOT_CHECKED, MAX_TOKEN_BYTES,
  verifyAnchor, datingSummary,
} from '../dist/index.js';

const F = new URL('./fixtures/rfc3161/', import.meta.url);
const bin = (p) => new Uint8Array(readFileSync(new URL(p, F)));
const stamped = bin('stamped.bin');
const record = JSON.parse(readFileSync(new URL('record.json', F), 'utf8'));
const b64 = (u8) => Buffer.from(u8).toString('base64');
const failed = (r) => r.checks.filter((c) => !c.ok).map((c) => c.what);

// ── a tiny DER tree, for rebuilding a token with one element replaced
const tlv = (buf, pos) => {
  const tag = buf[pos];
  let p = pos + 1;
  let len = buf[p++];
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[p++]; }
  return { tag, start: pos, body: p, end: p + len };
};
const tree = (buf, pos = 0) => {
  const n = tlv(buf, pos);
  const node = { tag: n.tag, raw: buf.subarray(n.start, n.end) };
  if (n.tag & 0x20) {
    node.kids = [];
    for (let p = n.body; p < n.end;) { const k = tree(buf, p); node.kids.push(k); p += k.raw.length; }
  }
  return node;
};
const lenBytes = (n) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff]);
const encode = (node) => {
  if (!node.kids) return node.raw;
  const body = Buffer.concat(node.kids.map(encode));
  return new Uint8Array(Buffer.concat([Buffer.from([node.tag, ...lenBytes(body.length)]), body]));
};
const replace = (node, from, to) => {
  if (Buffer.from(node.raw).equals(Buffer.from(from))) return { tag: to[0], raw: to };
  if (!node.kids) return node;
  return { tag: node.tag, kids: node.kids.map((k) => replace(k, from, to)) };
};
const indexOf = (hay, needle) => Buffer.from(hay).indexOf(Buffer.from(needle));

const POSITIVE = [
  ['rsa-sha256', 'RSASSA-PKCS1-v1_5', 'SHA-256', 'tsa-rsa'],
  ['rsa-sha512', 'RSASSA-PKCS1-v1_5', 'SHA-512', 'tsa-rsa'],
  ['p256-sha256', 'ECDSA', 'SHA-256', 'tsa-p256'],
  ['p384-sha384', 'ECDSA', 'SHA-384', 'tsa-p384'],
];

for (const [name, alg, imprint, cn] of POSITIVE) {
  test(`openssl token ${name} verifies (token, full response, base64)`, async () => {
    for (const form of [bin(`tokens/${name}.tst`), bin(`tokens/${name}.tsr`), b64(bin(`tokens/${name}.tst`))]) {
      const r = await verifyTimestampToken(form, stamped);
      assert.equal(r.ok, true, JSON.stringify(failed(r)));
      assert.match(r.genTime, /^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
      assert.equal(r.signerSubject, `C=US, O=VeilCore TEST ONLY, CN=TEST TSA ${cn}`);
      assert.equal(r.hashAlgorithm, imprint);
      assert.equal(r.policy, '1.3.6.1.4.1.99999.1');
      assert.ok(r.nonce, 'openssl ts -query sends a nonce');
      assert.ok(r.checks.some((c) => c.ok && c.what.includes(alg)));
      assert.ok(r.checks.some((c) => c.ok && /id-kp-timeStamping/.test(c.what)));
      assert.deepEqual(r.notChecked, ['certificate chain to a trusted root', 'qualified status on an EU trusted list', 'revocation']);
    }
  });
}

test('the stated limits are never dropped', () => {
  assert.deepEqual([...TIMESTAMP_NOT_CHECKED], ['certificate chain to a trusted root', 'qualified status on an EU trusted list', 'revocation']);
});

test('a token over different bytes fails on the imprint, and only there', async () => {
  const r = await verifyTimestampToken(bin('tokens/rsa-sha256.tst'), bin('other.bin'));
  assert.equal(r.ok, false);
  assert.deepEqual(failed(r), ['the imprint is the SHA-256 of the stamped bytes']);
  // The hex text of the commitment is not what is stamped: the raw 32 bytes are.
  const asText = new TextEncoder().encode(Buffer.from(stamped).toString('hex'));
  assert.equal((await verifyTimestampToken(bin('tokens/rsa-sha256.tst'), asText)).ok, false);
});

test('a tampered TSTInfo fails the messageDigest check', async () => {
  for (const name of ['rsa-sha256', 'p256-sha256']) {
    const t = bin(`tokens/${name}.tst`);
    const r0 = await verifyTimestampToken(t, stamped);
    // Move genTime by one year: same length, still a valid time.
    const at = indexOf(t, Buffer.from(r0.genTime.slice(0, 4)));
    assert.ok(at > 0);
    const bad = new Uint8Array(t);
    bad[at + 3] = bad[at + 3] === 0x39 ? 0x38 : bad[at + 3] + 1;
    const r = await verifyTimestampToken(bad, stamped);
    assert.equal(r.ok, false);
    assert.ok(failed(r).some((w) => /messageDigest/.test(w)), JSON.stringify(failed(r)));
    assert.notEqual(r.genTime, r0.genTime, 'the altered time is reported, and rejected');
  }
});

test('a tampered signature fails the signature check', async () => {
  for (const name of ['rsa-sha256', 'p256-sha256', 'p384-sha384']) {
    const bad = new Uint8Array(bin(`tokens/${name}.tst`));
    bad[bad.length - 1] ^= 0x01; // no unsigned attributes: the token ends with the signature
    const r = await verifyTimestampToken(bad, stamped);
    assert.equal(r.ok, false, name);
    assert.ok(failed(r).some((w) => /signature/.test(w)), JSON.stringify(failed(r)));
  }
});

test('a signer certificate without the timeStamping EKU fails, even though the signature holds', async () => {
  // Same key, issuer and serial; only the EKU is missing. The certificate set is outside
  // the signature, so nothing but the EKU check can catch this.
  const t = bin('tokens/rsa-sha256.tst');
  const swapped = encode(replace(tree(t), bin('certs/tsa-rsa.der'), bin('certs/tsa-rsa-noeku.der')));
  assert.notDeepEqual(swapped, t);
  const r = await verifyTimestampToken(swapped, stamped);
  assert.equal(r.ok, false);
  assert.deepEqual(failed(r), ['the signer certificate has the id-kp-timeStamping extended key usage']);
  assert.ok(r.checks.some((c) => c.ok && /signature over the signed attributes verifies/.test(c.what)));
});

test('a token without the signer certificate fails, unless the certificate is supplied', async () => {
  const t = tree(bin('tokens/rsa-sha256.tst'));
  // ContentInfo -> [0] -> SignedData; drop the [0] certificates field.
  const sd = t.kids[1].kids[0];
  sd.kids = sd.kids.filter((k) => k.tag !== 0xa0);
  const bare = encode(t);
  const r = await verifyTimestampToken(bare, stamped);
  assert.equal(r.ok, false);
  assert.deepEqual(failed(r), ['the signer certificate is present']);
  const r2 = await verifyTimestampToken(bare, stamped, { certificates: [bin('certs/tsa-rsa.der')] });
  assert.equal(r2.ok, true, JSON.stringify(failed(r2)));
});

test('unsupported algorithms are refused, not guessed at', async () => {
  const cases = [
    ['p521-sha256', /P-256 or P-384/],
    ['rsa-sha1-signer', /signer digest algorithm 1\.3\.14\.3\.2\.26/],
    ['rsa-sha1-imprint', /imprint hash algorithm 1\.3\.14\.3\.2\.26/],
  ];
  for (const [name, why] of cases) {
    const r = await verifyTimestampToken(bin(`tokens/${name}.tst`), stamped);
    assert.equal(r.ok, false, name);
    assert.ok(failed(r).some((w) => w.startsWith('unsupported:') && why.test(w)), `${name}: ${JSON.stringify(failed(r))}`);
  }
});

test('every truncation of a token fails cleanly', async () => {
  for (const name of ['rsa-sha256', 'p256-sha256']) {
    const t = bin(`tokens/${name}.tsr`);
    for (let n = 0; n < t.length; n++) {
      const r = await verifyTimestampToken(t.subarray(0, n), stamped);
      assert.equal(r.ok, false, `${name} cut at ${n}`);
    }
  }
});

test('trailing data is refused', async () => {
  const t = bin('tokens/rsa-sha256.tst');
  const r = await verifyTimestampToken(new Uint8Array([...t, 0]), stamped);
  assert.equal(r.ok, false);
  assert.match(failed(r)[0], /trailing data/);
});

test('huge, indefinite, non-minimal and deeply nested lengths are refused without allocating or looping', async () => {
  const cases = [
    [0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x02, 0x01, 0x00], // 2 GB claimed
    [0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00],               // five-byte length
    [0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00],               // indefinite (BER)
    [0x30, 0x81, 0x03, 0x02, 0x01, 0x00],                     // non-minimal
    [0x30, 0x82, 0x00, 0x03, 0x02, 0x01, 0x00],               // non-minimal, leading zero
    [0x3f, 0x81, 0x01, 0x00],                                 // high tag number
    [0x30, 0x02, 0x30, 0x05],                                 // child longer than parent
  ];
  for (const c of cases) {
    const r = await verifyTimestampToken(new Uint8Array(c), stamped);
    assert.equal(r.ok, false, JSON.stringify(c));
    assert.match(failed(r)[0], /^malformed token:/);
  }
  // 20,000 levels of validly nested SEQUENCEs: the parser descends only where a token's
  // structure says to, so depth in the input costs nothing.
  const headers = [];
  let size = 0;
  for (let i = 0; i < 20000; i++) {
    const h = [0x30, ...lenBytes(size)];
    headers.push(h);
    size += h.length;
  }
  const deep = new Uint8Array(headers.reverse().flat());
  assert.equal(deep.length, size);
  const rd = await verifyTimestampToken(deep, stamped);
  assert.equal(rd.ok, false);
  assert.match(failed(rd)[0], /^malformed token:/);
  const big = new Uint8Array(MAX_TOKEN_BYTES + 1);
  assert.match(failed(await verifyTimestampToken(big, stamped))[0], /larger than any timestamp token/);
  assert.match(failed(await verifyTimestampToken('not base64!', stamped))[0], /not valid base64/);
  assert.equal((await verifyTimestampToken('', stamped)).ok, false);
});

test('random corruption never throws, never hangs, and never passes inside the signed content', async () => {
  let seed = 3161;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32);
  const start = Date.now();
  // Anywhere in a full response: every call returns a result. Some corruptions pass, and
  // should: the certificate set (the CA certificate, the TSA certificate's own signature)
  // is not covered by a token check, because no chain is checked.
  const t = bin('tokens/p256-sha256.tsr');
  for (let i = 0; i < 2000; i++) {
    const bad = new Uint8Array(t);
    const flips = 1 + Math.floor(rnd() * 3);
    for (let f = 0; f < flips; f++) bad[Math.floor(rnd() * bad.length)] = Math.floor(rnd() * 256);
    const r = await verifyTimestampToken(bad, stamped);
    assert.equal(typeof r.ok, 'boolean');
  }
  // Inside the TSTInfo and the SignerInfo, which the signature is meant to protect, no
  // single changed byte may pass.
  for (const name of ['p256-sha256', 'rsa-sha256']) {
    const tok = bin(`tokens/${name}.tst`);
    const sd = tree(tok).kids[1].kids[0];
    const encap = sd.kids[2];
    const signers = sd.kids[sd.kids.length - 1];
    const regions = [encap, signers].map((n) => [indexOf(tok, n.raw), indexOf(tok, n.raw) + n.raw.length]);
    for (const [from, to] of regions) {
      for (let pos = from; pos < to; pos++) {
        const bad = new Uint8Array(tok);
        bad[pos] ^= 1 << Math.floor(rnd() * 8);
        const r = await verifyTimestampToken(bad, stamped);
        assert.equal(r.ok, false, `${name}: byte ${pos} changed and the token still passed`);
      }
    }
  }
  assert.ok(Date.now() - start < 120000);
});

test('timestampTokenBytes extracts the token from a response', () => {
  assert.deepEqual(timestampTokenBytes(bin('tokens/rsa-sha256.tsr')), bin('tokens/rsa-sha256.tst'));
  assert.deepEqual(timestampTokenBytes(b64(bin('tokens/rsa-sha256.tst'))), bin('tokens/rsa-sha256.tst'));
  assert.equal(timestampTokenBytes(new Uint8Array([0x30, 0x84, 0xff])), undefined);
});

// ── anchors

const tsaAnchor = (token) => ({ kind: 'rfc3161', chain: 'n/a', network: 'n/a', token: b64(token), tsa: 'TEST TSA' });

test('verifyAnchor checks an rfc3161 token against the record commitment by default', async () => {
  assert.equal(record.commitment, Buffer.from(stamped).toString('hex'));
  const v = await verifyAnchor(record, tsaAnchor(bin('tokens/p256-sha256.tst')));
  assert.equal(v.status, 'checked', v.what);
  assert.match(v.what, /Not checked: certificate chain to a trusted root/);
  const proof = JSON.parse(readFileSync(new URL('proof.json', F), 'utf8'));
  const batch = tsaAnchor(bin('tokens/batch-p256.tst'));
  assert.equal((await verifyAnchor(record, batch)).status, 'failed', 'a batch token does not stamp the record commitment');
  assert.equal((await verifyAnchor(record, batch, Buffer.from(proof.root, 'hex'))).status, 'checked');
});

test('verifyAnchor reports other kinds as lookups, and empty anchors as incomplete', async () => {
  const ledger = { kind: 'ledger', chain: 'midnight', network: 'preview', txHash: 'a'.repeat(64) };
  assert.equal((await verifyAnchor(record, ledger)).status, 'lookup');
  assert.equal((await verifyAnchor(record, { chain: 'midnight', network: 'undeployed' })).status, 'incomplete');
  assert.equal((await verifyAnchor(record, { kind: 'rfc3161', chain: 'n/a', network: 'n/a' })).status, 'incomplete');
  assert.equal((await verifyAnchor(record, { kind: 'opentimestamps', chain: 'bitcoin', network: 'mainnet', ots: 'AA==' })).status, 'lookup');
  assert.equal((await verifyAnchor(record, tsaAnchor(new Uint8Array([1, 2, 3])))).status, 'failed');
});

test('datingSummary says checked versus stated when given results', async () => {
  const ledger = { kind: 'ledger', chain: 'midnight', network: 'preview', txHash: 'a'.repeat(64) };
  const good = { ...tsaAnchor(bin('tokens/rsa-sha256.tst')), qualified: { scheme: 'eIDAS' } };
  const env = { ...record, anchor: [ledger, good] };
  const results = await Promise.all([ledger, good].map((a) => verifyAnchor(env, a)));
  const s = datingSummary(env, results);
  assert.match(s, /Checked: 1 timestamp token, the earliest at 20/);
  assert.match(s, /certificate chain, trusted-list status and revocation were not checked/);
  assert.match(s, /Stated only: 1 anchor/);
  assert.match(s, /Qualified status is stated, not checked/);
  assert.match(datingSummary(env), /None is checked by this summary/, 'without results nothing is called checked');

  const tampered = new Uint8Array(bin('tokens/rsa-sha256.tst'));
  tampered[tampered.length - 1] ^= 1;
  const bad = tsaAnchor(tampered);
  const env2 = { ...record, anchor: [bad] };
  const s2 = datingSummary(env2, [await verifyAnchor(env2, bad)]);
  assert.match(s2, /Failed: 1 anchor did not check out/);
  assert.match(s2, /Nothing establishes when this record was made/);
  assert.doesNotMatch(s2, /Checked:/);
});
