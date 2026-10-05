// Malformed and inconsistent input, across every verifier.
//
// The rule: a verification function returns a clean failure. It never reports "valid" for
// something malformed, and never throws (an exception in a verifier takes down the caller
// that wrote `if (!(await verify(x)))`). Each test below is input that, before the round D
// review (Oct 2026), either verified when it should not have or threw.
// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash, webcrypto } from 'node:crypto';
import {
  canonicalise, computeCommitment, verifyCommitment, verifyFieldSet, buildBatch, verifyInclusion,
  generateKeypair, signAttestation, verifyAttestation, verifyRetraction, verifyChallenge, verifiedStrengthOf, strengthOf,
  contestedStatus, diffRecords, classifyCorrection, parseQualifiedId, isRegistryAuthority, resolveRegistry, resolveRecord,
  verifyAgainstRegistry, verifyAnchor, verifyTimestampToken, decodeBase64, buildEvidencePackage, verifyEvidencePackage,
  fieldSchemaId, typedSlotValues, sealFieldSet, fieldSetRootOf, rootFromOpening, openFieldSlot, toHex, COMMITMENT_ALGORITHM,
} from '../dist/index.js';

const H = (c) => c.repeat(64);
const noThrow = async (what, f) => {
  try {
    return await f();
  } catch (e) {
    assert.fail(`${what} threw: ${e?.message ?? e}`);
  }
};

const record = async (id = 'vc_rec_hard', extra = {}) => {
  const r = {
    formatVersion: '0.1', recordId: id, subjectType: 'plant-variety', profile: 'veilcore/profile/plant-variety/v1',
    commitment: '', commitmentAlgorithm: COMMITMENT_ALGORITHM, anchor: { chain: 'midnight', network: 'preprod' },
    sealedAt: '2026-10-03T12:00:00Z', holder: { id: 'vc_hld_test' }, parents: [], attestations: [],
    profileData: { denomination: 'Harbour Mist', nonce: createHash('sha256').update(id).digest('hex') }, ...extra,
  };
  r.commitment = await computeCommitment(r);
  return r;
};

// ───────────────────────────────────────────────────────── inclusion proofs (SPEC 5)

test('inclusion: every operand must be 64 lowercase hex, every flag a boolean', async () => {
  const cs = [H('1'), H('2'), H('3')];
  const b = await buildBatch(cs, 'B');
  const good = b.proofs[H('2')];
  assert.equal(await verifyInclusion(good), true);
  const variants = {
    'uppercase commitment': { ...good, commitment: H('A') },
    'uppercase root': { ...good, root: good.root.toUpperCase() },
    'short sibling': { ...good, path: [{ ...good.path[0], sibling: good.path[0].sibling.slice(2) }, ...good.path.slice(1)] },
    'uppercase sibling': { ...good, path: [{ ...good.path[0], sibling: good.path[0].sibling.toUpperCase() }, ...good.path.slice(1)] },
    'sibling with padding': { ...good, path: [{ ...good.path[0], sibling: good.path[0].sibling + ' ' }, ...good.path.slice(1)] },
    'flag as string': { ...good, path: [{ ...good.path[0], siblingIsLeft: 'false' }, ...good.path.slice(1)] },
    'flag as number': { ...good, path: [{ ...good.path[0], siblingIsLeft: 0 }, ...good.path.slice(1)] },
    'sparse path': { ...good, path: [, ...good.path] }, // eslint-disable-line no-sparse-arrays
    'path not a list': { ...good, path: 'x' },
    'too deep': { ...good, path: Array.from({ length: 65 }, () => ({ sibling: H('0'), siblingIsLeft: true })) },
    'null': null,
    'string': 'proof',
    'throwing getter': Object.defineProperty({ ...good }, 'path', { get() { throw new Error('boom'); } }),
  };
  for (const [name, p] of Object.entries(variants)) {
    assert.equal(await noThrow(name, () => verifyInclusion(p)), false, name);
  }
});

test('a batch is refused for anything that is not a 64-hex commitment (SPEC 5.1)', async () => {
  for (const bad of [[H('A')], ['abc'], [H('1'), 42], 'x']) {
    await assert.rejects(buildBatch(bad, 'B'));
  }
});

test('Python fold_proof refuses the same malformed steps (no truthiness, no odd lengths)', () => {
  const fold = (input) => spawnSync('python3', ['conformance/impl.py'], { input: JSON.stringify({ op: 'fold', input }), encoding: 'utf8' });
  assert.equal(fold({ commitment: H('1'), path: [{ sibling: H('2'), siblingIsLeft: true }] }).status, 0);
  for (const input of [
    { commitment: H('1'), path: [{ sibling: H('2'), siblingIsLeft: 'yes' }] },
    { commitment: H('1'), path: [{ sibling: H('2').slice(1), siblingIsLeft: true }] },
    { commitment: H('A'), path: [] },
    { commitment: H('1'), path: 'x' },
  ]) {
    assert.notEqual(fold(input).status, 0, JSON.stringify(input));
  }
});

// ───────────────────────────────────────────────────────── canonical form and commitments

test('canonicalise refuses values JSON cannot carry instead of hashing something else', () => {
  assert.throws(() => canonicalise([1, , 2]), /missing element/); // eslint-disable-line no-sparse-arrays
  const cyc = { a: 1 };
  cyc.self = cyc;
  assert.throws(() => canonicalise(cyc), /contains itself/);
  const arr = [];
  arr.push(arr);
  assert.throws(() => canonicalise(arr), /contains itself/);
  assert.throws(() => canonicalise({ b: new Uint8Array([1, 2]) }), /binary/);
  // The same value twice, not nested, is fine: only a cycle is refused.
  const shared = { x: 1 };
  assert.equal(canonicalise({ a: shared, b: shared }), '{"a":{"x":1},"b":{"x":1}}');
});

test('verifyCommitment never throws, whatever it is handed', async () => {
  const deep = {};
  let d = deep;
  for (let i = 0; i < 20000; i++) d = d.x = {};
  const r = await record();
  const cyc = { ...r, profileData: { ...r.profileData } };
  cyc.profileData.self = cyc.profileData;
  for (const [name, v] of Object.entries({
    null: null, undefined, array: [], string: 'x', number: 1,
    'deep nesting': { ...r, profileData: deep },
    cycle: cyc,
    'symbol algorithm': { ...r, commitmentAlgorithm: Symbol('x') },
  })) {
    const out = await noThrow(name, () => verifyCommitment(v));
    assert.equal(out.valid, false, name);
    assert.equal(typeof out.reason, 'string', name);
  }
  assert.equal((await verifyCommitment(r)).valid, true);
});

// ───────────────────────────────────────────────────────── field sets (SPEC 4.5)

const fieldsFixture = async () => {
  const v = JSON.parse(readFileSync(new URL('../conformance/vectors.json', import.meta.url), 'utf8')).fieldSets[0].input;
  const schemaId = await fieldSchemaId(v.schema);
  const values = await typedSlotValues(v.schema, v.values);
  const fs = await sealFieldSet(schemaId, values, Uint8Array.from(Buffer.from(v.fieldSecret, 'hex')));
  const env = await record('vc_rec_fields', {
    commitmentAlgorithm: 'sha256/fields/v1', fieldSchema: toHex(schemaId), fieldSetRoot: toHex(await fieldSetRootOf(fs)),
  });
  return { env, fs };
};

test('verifyFieldSet: a genuine set verifies; a malformed one is refused without throwing', async () => {
  const { env, fs } = await fieldsFixture();
  assert.equal((await verifyFieldSet(env, fs)).valid, true);
  // Plain arrays of numbers used to be copied into buffers, where 256 becomes 0.
  const asArrays = { schemaId: Array.from(fs.schemaId), values: fs.values.map((x) => Array.from(x)), salts: fs.salts.map((x) => Array.from(x)) };
  const wrapped = { ...fs, values: fs.values.map((x) => Array.from(x, (b) => b + 256)) };
  for (const [name, bad] of Object.entries({
    null: null, 'plain arrays': asArrays, 'wrapped bytes': wrapped,
    'fifteen values': { ...fs, values: fs.values.slice(1) },
    'no salts': { ...fs, salts: undefined },
    'short salt': { ...fs, salts: fs.salts.map((s, i) => (i === 3 ? s.slice(1) : s)) },
  })) {
    const out = await noThrow(name, () => verifyFieldSet(env, bad));
    assert.equal(out.valid, false, name);
  }
  for (const badEnv of [null, { ...env, fieldSetRoot: env.fieldSetRoot.toUpperCase() }, { ...env, fieldSchema: undefined }]) {
    assert.equal((await noThrow('env', () => verifyFieldSet(badEnv, fs))).valid, false);
  }
});

test('an opening must carry 16 real 32-byte leaves', async () => {
  const { fs } = await fieldsFixture();
  const o = await openFieldSlot(fs, 2);
  assert.equal(toHex(await rootFromOpening(fs.schemaId, o)), toHex(await fieldSetRootOf(fs)));
  await assert.rejects(rootFromOpening(fs.schemaId, { ...o, leaves: o.leaves.map((l) => Array.from(l)) }), /32 bytes/);
  await assert.rejects(rootFromOpening(fs.schemaId, null), /object/);
});

// ───────────────────────────────────────────────────────── signatures (SPEC 7)

const draft = (publicKey) => ({
  attestationId: 'att_h', type: 'laboratory-report', subjectCommitment: H('a'),
  attester: { publicKey, displayName: 'Example Laboratory' }, documentHash: H('c'), hashAlgorithm: 'sha256', issuedAt: '2026-10-01T00:00:00Z',
});

test('a small-order Ed25519 key does not make every message "signed"', async () => {
  // Identity point, R = identity, S = 0: WebCrypto's cofactorless check accepts this for
  // ANY message. Before the fix it reported signed-and-accredited for content nobody signed.
  const identity = '01' + '00'.repeat(31);
  const forged = { ...draft(identity), attester: { publicKey: identity, accreditation: { scheme: 'ISO/IEC 17025', identifier: '1', accreditor: 'X' } }, signature: identity + '00'.repeat(32), signatureAlgorithm: 'ed25519' };
  assert.equal(await webcrypto.subtle.verify('Ed25519', await webcrypto.subtle.importKey('raw', Buffer.from(identity, 'hex'), { name: 'Ed25519' }, false, ['verify']), Buffer.from(forged.signature, 'hex'), Buffer.from('anything')), true, 'the platform accepts it, which is why the SDK must not');
  assert.equal(await verifyAttestation(forged), false);
  assert.equal(await verifiedStrengthOf(forged), 'invalid-signature');
  assert.equal(strengthOf(forged), 'signed-and-accredited', 'strengthOf reports the claim only, and says so');
  // The same point spelt non-canonically (y = p + 1), and the order-2 and order-4 points.
  for (const k of ['ee' + 'ff'.repeat(30) + '7f', 'ec' + 'ff'.repeat(30) + '7f', '00'.repeat(32), '00'.repeat(31) + '80', 'ed' + 'ff'.repeat(30) + 'ff']) {
    assert.equal(await verifyAttestation({ ...forged, attester: { publicKey: k } }), false, k);
  }
});

test('one signature has one spelling, and one key one spelling', async () => {
  const kp = await generateKeypair();
  const signed = await signAttestation(draft(kp.publicKey), kp.privateKey);
  assert.equal(await verifyAttestation(signed), true);
  assert.equal(await verifiedStrengthOf(signed), 'signed');
  const variants = {
    'uppercase signature': { ...signed, signature: signed.signature.toUpperCase() },
    // parseInt('0g', 16) is 0, so the old reader took "0g" as the byte 00.
    'non-hex character': { ...signed, signature: `${signed.signature[0]}g${signed.signature.slice(2)}` },
    'odd length': { ...signed, signature: signed.signature + '0' },
    'truncated': { ...signed, signature: signed.signature.slice(0, 126) },
    'signature as a number': { ...signed, signature: 5 },
    'uppercase key': { ...signed, attester: { ...signed.attester, publicKey: signed.attester.publicKey.toUpperCase() } },
    'other algorithm named': { ...signed, signatureAlgorithm: 'rsa' },
    'no attester': { ...signed, attester: undefined },
    'null': null,
    'array': [],
  };
  for (const [name, v] of Object.entries(variants)) {
    assert.equal(await noThrow(name, () => verifyAttestation(v)), false, name);
  }
  assert.equal(await noThrow('retraction null', () => verifyRetraction(null, signed)), false);
  assert.equal(await noThrow('retraction vs null', () => verifyRetraction({ attestationId: 'x', signature: 'y' }, null)), false);
  assert.equal(await noThrow('challenge null', () => verifyChallenge(null)), false);
  assert.equal(await noThrow('challenge no challenger', () => verifyChallenge({ signature: 'a', claimCommitment: H('1') })), false);
  await assert.rejects(signAttestation(draft(kp.publicKey), kp.privateKey.toUpperCase()), /lowercase hex/);
});

test('an attestation signed without its subject is not a signature about any record', async () => {
  // The payload builder omits an absent field, so this signs and would verify anywhere it
  // was pasted. SPEC 7: subjectCommitment is what stops that.
  const kp = await generateKeypair();
  const { subjectCommitment, ...portable } = draft(kp.publicKey);
  const signed = await signAttestation(portable, kp.privateKey);
  assert.equal(await verifyAttestation(signed), false);
  for (const [k, v] of [['subjectCommitment', H('A')], ['hashAlgorithm', 'md5'], ['issuedAt', '']]) {
    const s2 = await signAttestation({ ...draft(kp.publicKey), [k]: v }, kp.privateKey);
    assert.equal(await verifyAttestation(s2), false, k);
  }
});

// ───────────────────────────────────────────────────────── challenges and corrections

test('a challenge state this version does not know counts as open, not "answered"', () => {
  const s = contestedStatus([{ state: 'closed-by-relay', ground: 'descent' }]);
  assert.equal(s.open, 1);
  assert.equal(s.contested, true);
  assert.doesNotMatch(s.summary, /holder has answered/);
  assert.equal(contestedStatus(null).contested, false);
  assert.equal(contestedStatus([null, 'x']).contested, false);
});

test('a key outside the commitment cannot hide a material change from diffRecords', () => {
  const before = {
    formatVersion: '0.1', recordId: 'r1', subjectType: 'plant-variety', profile: 'p', commitment: H('a'),
    commitmentAlgorithm: COMMITMENT_ALGORITHM, sealedAt: '2026-01-01T00:00:00Z', holder: { id: 'h' },
    subject: { name: 'X', taxon: 'Cannabis sativa' }, profileData: { notes: '' },
  };
  // subject.taxon changes (material for descent), and an uncommitted top-level key
  // "subject.taxon" holding the old value is added after it. It used to overwrite the
  // flattened path and the correction came out cosmetic with no changed fields.
  const after = { ...before, recordId: 'r2', subject: { name: 'X', taxon: 'Humulus lupulus' }, 'subject.taxon': 'Cannabis sativa' };
  const changes = diffRecords(before, after);
  assert.ok(changes.some((c) => c.field === 'subject.taxon'), JSON.stringify(changes));
  assert.equal(classifyCorrection(changes).descent, 'material');
  // A collision inside committed content is reported, not resolved.
  const b2 = { ...before, profileData: { notes: '', a: { b: 1 } } };
  const a2 = { ...before, profileData: { notes: '', a: { b: 2 }, 'a.b': 1 } };
  const c2 = diffRecords(b2, a2);
  assert.ok(c2.some((c) => c.field === 'profileData.a.b' && c.severity.descent === 'material'), JSON.stringify(c2));
});

// ───────────────────────────────────────────────────────── resolution and registry checks

const withFetch = async (impl, body) => {
  const real = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return impl(String(url), init);
  };
  try {
    return { result: await body(), calls };
  } finally {
    globalThis.fetch = real;
  }
};

test('an authority is a public DNS name: no IP literal, no single label, nothing that bends the URL', async () => {
  for (const ok of ['northfield.example.com', 'x.example', 'a-b.example.org']) assert.equal(isRegistryAuthority(ok), true, ok);
  for (const bad of ['127.0.0.1', '169.254.169.254', 'localhost', 'a..b', '.example.com', 'example.com.', '-x.example', 'evil.com/x?', 'user@host.com', 'host.com:8443', '', 'x'.repeat(64) + '.com']) {
    assert.equal(isRegistryAuthority(bad), false, bad);
  }
  assert.equal(parseQualifiedId('vc:169.254.169.254/latest'), null);
  assert.equal(parseQualifiedId('vc:localhost/x'), null);
  assert.equal(parseQualifiedId(`vc:x.example/${'a'.repeat(600)}`), null);
  const { result, calls } = await withFetch(() => new Response('{}'), () => resolveRegistry('169.254.169.254'));
  assert.equal(result, null);
  assert.equal(calls.length, 0, 'nothing is requested for an authority that is not a DNS name');
});

test('resolution refuses redirects and oversized answers', async () => {
  const { calls } = await withFetch(() => new Response(JSON.stringify({ api: 'https://reg.x.example/api' })), () => resolveRecord('vc:x.example/LAB-1'));
  assert.ok(calls.length >= 1 && calls.every((c) => c.init?.redirect === 'error'), JSON.stringify(calls.map((c) => c.init)));
  const huge = JSON.stringify({ api: 'https://x.example/', pad: 'a'.repeat(2 * 1024 * 1024) });
  assert.equal((await withFetch(() => new Response(huge), () => resolveRegistry('x.example'))).result, null);
  const typed = JSON.stringify({ api: 'https://x.example/', formatVersions: 'not a list' });
  assert.equal((await withFetch(() => new Response(typed), () => resolveRegistry('x.example'))).result, null);
  const creds = JSON.stringify({ api: 'https://user:pw@x.example/' });
  assert.equal((await withFetch(() => new Response(creds), () => resolveRegistry('x.example'))).result, null);
});

test('verifyAgainstRegistry reports an erroring or unusable registry instead of trusting its body', async () => {
  const r = await record();
  const { result } = await withFetch(() => new Response(JSON.stringify({ found: true, commitment: r.commitment }), { status: 500 }), () => verifyAgainstRegistry(r, 'https://reg.example'));
  assert.equal(result.intact, true);
  assert.equal(result.matchesRegistry, undefined, 'a 500 body is not a registry answer');
  assert.ok(result.reasons.some((x) => /HTTP 500/.test(x)));
  const bad = await withFetch(() => new Response('{}'), () => verifyAgainstRegistry(r, 'file:///etc/passwd'));
  assert.equal(bad.calls.length, 0);
  assert.ok(bad.result.reasons.some((x) => /not an http/.test(x)));
  assert.equal((await noThrow('null record', () => verifyAgainstRegistry(null, 'https://reg.example'))).intact, false);
});

// ───────────────────────────────────────────────────────── anchors and RFC 3161

test('verifyAnchor never throws on a malformed anchor or stamped bytes', async () => {
  const r = await record();
  for (const [name, a, bytes] of [
    ['null anchor', null, undefined],
    ['string anchor', 'x', undefined],
    ['token not a string', { kind: 'rfc3161', token: 42 }, undefined],
    ['stamped bytes wrong length', { kind: 'rfc3161', token: 'AAAA' }, new Uint8Array(3)],
    ['stamped bytes not bytes', { kind: 'rfc3161', token: 'AAAA' }, [1, 2, 3]],
  ]) {
    const out = await noThrow(name, () => verifyAnchor(r, a, bytes));
    assert.equal(out.status, 'failed', name);
  }
  assert.equal((await noThrow('null record', () => verifyAnchor(null, { kind: 'rfc3161', token: 'AAAA' }))).status, 'failed');
});

test('base64 has one spelling per byte string', () => {
  assert.deepEqual([...decodeBase64('AA==')], [0]);
  assert.deepEqual([...decodeBase64('AA')], [0]);
  assert.deepEqual([...decodeBase64(' A A = = ')], [0]);
  for (const bad of ['AB==', 'AA=', 'AA===', 'AAA==', 'A', 'AA*A', 'AAA=A']) assert.throws(() => decodeBase64(bad), /base64/, bad);
});

// A tiny DER tree, to rebuild a token with one element changed.
const tlv = (buf, pos) => {
  let p = pos + 1;
  let len = buf[p++];
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[p++]; }
  return { tag: buf[pos], start: pos, body: p, end: p + len };
};
const tree = (buf, pos = 0) => {
  const n = tlv(buf, pos);
  const node = { tag: n.tag, raw: buf.subarray(n.start, n.end) };
  if (n.tag & 0x20) { node.kids = []; for (let p = n.body; p < n.end;) { const k = tree(buf, p); node.kids.push(k); p += k.raw.length; } }
  return node;
};
const lenBytes = (n) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff]);
const der = (tag, body) => new Uint8Array(Buffer.concat([Buffer.from([tag, ...lenBytes(body.length)]), Buffer.from(body)]));
const encode = (node) => (node.kids ? der(node.tag, Buffer.concat(node.kids.map(encode))) : node.raw);

const F = new URL('./fixtures/rfc3161/', import.meta.url);
const fbin = (p) => new Uint8Array(readFileSync(new URL(p, F)));

test('an ECDSA signature has one encoding: a padded or negative r is refused, not normalised', async () => {
  const stamped = fbin('stamped.bin');
  const t = tree(fbin('tokens/p256-sha256.tst'));
  assert.equal((await verifyTimestampToken(encode(t), stamped)).ok, true);
  const si = t.kids[1].kids[0].kids.at(-1).kids[0];
  const sigNode = si.kids.at(-1);
  const sig = tree(sigNode.raw.subarray(tlv(sigNode.raw, 0).body)); // ECDSA-Sig-Value
  const [r, s] = sig.kids;
  const rBody = r.raw.subarray(tlv(r.raw, 0).body);
  const variants = {
    'r with a redundant leading zero': der(0x30, Buffer.concat([der(0x02, [0, ...rBody]), s.raw])),
    'extra element': der(0x30, Buffer.concat([r.raw, s.raw, der(0x02, [1])])),
  };
  if (rBody[0] === 0 && rBody[1] & 0x80) {
    variants['r written as negative'] = der(0x30, Buffer.concat([der(0x02, rBody.subarray(1)), s.raw]));
  }
  for (const [name, inner] of Object.entries(variants)) {
    si.kids[si.kids.length - 1] = { tag: 0x04, raw: der(0x04, inner) };
    const out = await verifyTimestampToken(encode(t), stamped);
    assert.equal(out.ok, false, name);
    assert.ok(out.checks.some((c) => !c.ok && /malformed token/.test(c.what)), `${name}: ${JSON.stringify(out.checks)}`);
  }
});

test('a TimeStampResp with trailing fields, or a token with extra content, is refused', async () => {
  const stamped = fbin('stamped.bin');
  const resp = tree(fbin('tokens/rsa-sha256.tsr'));
  resp.kids.push({ tag: 0x05, raw: new Uint8Array([0x05, 0x00]) });
  assert.equal((await verifyTimestampToken(encode(resp), stamped)).ok, false);
  const tok = tree(fbin('tokens/rsa-sha256.tst'));
  tok.kids.push({ tag: 0x05, raw: new Uint8Array([0x05, 0x00]) });
  assert.equal((await verifyTimestampToken(encode(tok), stamped)).ok, false);
  for (const junk of [null, 42, {}, 'not base64 at all!', new Uint8Array(0), new Uint8Array([0x30, 0x84, 0xff, 0xff, 0xff, 0xff])]) {
    assert.equal((await noThrow(String(junk), () => verifyTimestampToken(junk, stamped))).ok, false);
  }
});

// ───────────────────────────────────────────────────────── evidence packages

const write = (files) => {
  const dir = mkdtempSync(join(tmpdir(), 'vc-hard-'));
  for (const [n, b] of Object.entries(files)) writeFileSync(join(dir, n), b);
  return dir;
};
const runPy = (dir) => spawnSync('python3', [join(dir, 'verify.py')], { encoding: 'utf8' });
const enc = (v) => new TextEncoder().encode(typeof v === 'string' ? v : JSON.stringify(v));

const evidenceFixture = async () => {
  const recs = await Promise.all(['a', 'b', 'c'].map((x) => record(`vc_rec_hd_${x}`)));
  const batch = await buildBatch(recs.map((r) => r.commitment), 'B-HARD', '2026-10-03T12:05:00Z');
  const proof = batch.proofs[recs[1].commitment];
  return { rec: recs[1], proof, files: await buildEvidencePackage({ record: recs[1], proof }) };
};

test('verifyEvidencePackage reports malformed packages as failed checks, never throws', async () => {
  const { files } = await evidenceFixture();
  assert.equal((await verifyEvidencePackage(files)).ok, true);
  const manifest = JSON.parse(new TextDecoder().decode(files['MANIFEST.json']));
  const cases = {
    'no files': null,
    'manifest not JSON': { ...files, 'MANIFEST.json': enc('{') },
    'manifest not UTF-8': { ...files, 'MANIFEST.json': new Uint8Array([0xff, 0xfe]) },
    'manifest without files': { ...files, 'MANIFEST.json': enc({ format: 'veilcore-evidence/v1' }) },
    'manifest of another format': { ...files, 'MANIFEST.json': enc({ ...manifest, format: 'x' }) },
    'manifest naming a path': { ...files, 'MANIFEST.json': enc({ ...manifest, files: { ...manifest.files, '../../etc/passwd': H('0') } }) },
    'manifest listing nothing': { ...files, 'MANIFEST.json': enc({ ...manifest, files: {} }) },
    'file added after building': { ...files, 'claims.json': enc([{ claim: 'unverified' }]) },
    'record not an object': { ...files, 'record.json': enc('[]') },
    'proof is null': { ...files, 'inclusion-proof.json': enc('null') },
    'proof with uppercase sibling': { ...files, 'inclusion-proof.json': enc({ ...JSON.parse(new TextDecoder().decode(files['inclusion-proof.json'])), path: [{ sibling: H('A'), siblingIsLeft: true }] }) },
    'manifest names another commitment': { ...files, 'MANIFEST.json': enc({ ...manifest, commitment: H('0') }) },
  };
  for (const [name, f] of Object.entries(cases)) {
    const out = await noThrow(name, () => verifyEvidencePackage(f));
    assert.equal(out.ok, false, name);
  }
});

test('verify.py fails cleanly (no traceback) on the same malformed packages', async () => {
  const { files } = await evidenceFixture();
  const manifest = JSON.parse(new TextDecoder().decode(files['MANIFEST.json']));
  const proof = JSON.parse(new TextDecoder().decode(files['inclusion-proof.json']));
  const cases = {
    'manifest not JSON': { ...files, 'MANIFEST.json': enc('{') },
    'manifest without files': { ...files, 'MANIFEST.json': enc({ format: 'veilcore-evidence/v1' }) },
    'manifest naming an absolute path': { ...files, 'MANIFEST.json': enc({ ...manifest, files: { ...manifest.files, '/etc/hostname': H('0') } }) },
    'file added after building': { ...files, 'notes.txt': enc('added') },
    'record not an object': { ...files, 'record.json': enc('[]') },
    'record not JSON': { ...files, 'record.json': enc('{') },
    'proof without a path': { ...files, 'inclusion-proof.json': enc({ ...proof, path: undefined }) },
    'proof with a non-boolean flag': { ...files, 'inclusion-proof.json': enc({ ...proof, path: proof.path.map((s) => ({ ...s, siblingIsLeft: s.siblingIsLeft ? 1 : 0 })) }) },
  };
  const { 'MANIFEST.json': _, ...withoutManifest } = files;
  cases['no manifest'] = withoutManifest;
  for (const [name, f] of Object.entries(cases)) {
    const r = runPy(write(f));
    assert.equal(r.status, 1, `${name}\n${r.stdout}${r.stderr}`);
    assert.doesNotMatch(r.stderr, /Traceback/, name);
    assert.match(r.stdout, /SOME CHECKS FAILED/, name);
  }
});

test('verify.py: a .tst file must BE the stated token, not a fragment of it', async () => {
  const rec = JSON.parse(readFileSync(new URL('record.json', F), 'utf8'));
  rec.anchor = [{ kind: 'rfc3161', chain: 'n/a', network: 'n/a', token: Buffer.from(fbin('tokens/rsa-sha256.tsr')).toString('base64') }];
  const files = await buildEvidencePackage({ record: rec });
  assert.equal(runPy(write(files)).status, 0);
  // Replace the token file with a fragment of the stated response and rewrite the
  // manifest to match (the manifest is not the defence; this check is).
  const fragment = files['rfc3161-record-1.tst'].subarray(0, 40);
  const m = JSON.parse(new TextDecoder().decode(files['MANIFEST.json']));
  m.files['rfc3161-record-1.tst'] = createHash('sha256').update(fragment).digest('hex');
  const r = runPy(write({ ...files, 'rfc3161-record-1.tst': fragment, 'MANIFEST.json': enc(m) }));
  assert.equal(r.status, 1, r.stdout);
  assert.match(r.stdout, /rfc3161-record-1\.tst is not the token the record states/);
  assert.equal((await verifyEvidencePackage({ ...files, 'rfc3161-record-1.tst': fragment, 'MANIFEST.json': enc(m) })).ok, false);
});

test('an OpenTimestamps file is only packaged, and only passes, with the proof that ties its root to the record', async () => {
  const { rec, proof } = await evidenceFixture();
  const rootBin = Buffer.from(proof.root, 'hex');
  await assert.rejects(buildEvidencePackage({ record: rec, opentimestamps: { rootBin, ots: new Uint8Array(60) } }), /inclusion proof/);
  const header = Buffer.concat([Buffer.from('\x00OpenTimestamps\x00\x00Proof\x00', 'latin1'), Buffer.from([0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94])]);
  const ots = Buffer.concat([header, Buffer.from([0x01, 0x08]), createHash('sha256').update(rootBin).digest(), Buffer.from([0x00])]);
  const files = await buildEvidencePackage({ record: rec, proof, opentimestamps: { rootBin, ots } });
  assert.equal((await verifyEvidencePackage(files)).ok, true);
  // Version byte other than 1, or a digest of something else: refused by both checkers.
  for (const bad of [Buffer.concat([header, Buffer.from([0x02]), ots.subarray(header.length + 1)]), Buffer.concat([header, Buffer.from([0x01, 0x08]), Buffer.alloc(32), Buffer.from([0])])]) {
    const m = JSON.parse(new TextDecoder().decode(files['MANIFEST.json']));
    m.files['root.bin.ots'] = createHash('sha256').update(bad).digest('hex');
    const f = { ...files, 'root.bin.ots': new Uint8Array(bad), 'MANIFEST.json': enc(m) };
    assert.equal((await verifyEvidencePackage(f)).ok, false);
    assert.equal(runPy(write(f)).status, 1);
  }
});
