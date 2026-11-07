// A record that names its own key (SPEC 3.6.1).
//
// Every key-bound vector, in both entry points and in the Python implementation; the
// vectors in the shared set are exactly the published key-bound-v1.json; older records
// keep their fingerprint; and the verifier functions refuse rather than throw.
import { test } from 'node:test';
import assert from 'node:assert';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as node from '../dist/index.js';
import * as browser from '../dist/index.browser.js';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const V = JSON.parse(readFileSync(here('../conformance/vectors.json'), 'utf8'));
const PUBLISHED = JSON.parse(readFileSync(here('../conformance/key-bound-v1.json'), 'utf8'));
/** What a refusal says: a malformed keyBinding, or a field set that isn't whole (SPEC 3.6.1, 4.5). */
const REFUSED = /keyBinding must be 64 lowercase hex|fieldSchema and fieldSetRoot come together/;

test('the shared set carries the published key-bound vectors unchanged, and all of them', () => {
  assert.deepEqual(V.keyBoundKeys, PUBLISHED.keys);
  assert.deepEqual(V.keyBoundRecords, PUBLISHED.records);
  assert.deepEqual(V.keyBoundChecks, PUBLISHED.checks);
  assert.deepEqual(V.keyBoundRefusals, PUBLISHED.refusals);
  assert.deepEqual([V.keyBoundKeys.length, V.keyBoundRecords.length, V.keyBoundChecks.length, V.keyBoundRefusals.length], [2, 6, 11, 9]);
  // Positive and negative cases are both there: a set of only matches tests half of it.
  assert.ok(V.keyBoundChecks.some((c) => c.matches) && V.keyBoundChecks.some((c) => !c.matches));
  assert.ok(V.keyBoundChecks.some((c) => /swapped/.test(c.name) && !c.matches));
});

for (const [entry, impl] of [['node', node], ['browser', browser]]) {
  test(`${entry}: keys from the record secret`, async () => {
    for (const k of V.keyBoundKeys) {
      assert.equal(await impl.identityFromSecret(k.recordSecret), k.identity);
      assert.equal(await impl.keySaltOf(k.recordSecret), k.keySalt);
      assert.equal(await impl.keyBindingOf(k.identity, k.keySalt), k.keyBinding);
      assert.deepEqual(await impl.bindingForSecret(k.recordSecret), { identity: k.identity, keySalt: k.keySalt, keyBinding: k.keyBinding });
    }
  });

  test(`${entry}: every record, older and bound: canonical text, content hash, fingerprint, algorithm`, async () => {
    for (const r of V.keyBoundRecords) {
      assert.equal(impl.canonicalise(r.fields), r.canonical, r.name);
      assert.deepEqual(await impl.computeRecordFingerprint(r.fields), { algorithm: r.algorithm, contentHash: r.contentHash, fingerprint: r.fingerprint }, r.name);
      assert.deepEqual(await impl.verifyRecordFingerprint({ fields: r.fields, fingerprint: r.fingerprint, algorithm: r.algorithm }), { valid: true, computed: r.fingerprint }, r.name);
      if (r.fields.keyBinding) assert.equal(await impl.keyBoundFingerprint(r.fields.keyBinding, r.contentHash), r.fingerprint, r.name);
    }
  });

  test(`${entry}: every check: a key matches only the record that named it`, async () => {
    for (const c of V.keyBoundChecks) {
      assert.equal(await impl.keyMatchesRecord(c.identity, { fingerprint: c.fingerprint, keySalt: c.keySalt, contentHash: c.contentHash }), c.matches, c.name);
    }
  });

  test(`${entry}: every refusal: a malformed keyBinding or a half field set is refused, not hashed`, async () => {
    for (const r of V.keyBoundRefusals) {
      await assert.rejects(() => impl.computeRecordFingerprint(r.fields), REFUSED, r.name);
      const v = await impl.verifyRecordFingerprint({ fields: r.fields, fingerprint: 'ab'.repeat(32) });
      assert.equal(v.valid, false, r.name);
      assert.match(v.reason, REFUSED, r.name);
    }
  });
}

test('is plain SHA-256 over the padded tag and 32-byte pieces, so any language can check it', async () => {
  const H = (tag, ...hex) => {
    const t = Buffer.alloc(32);
    t.write(tag, 'utf8');
    return createHash('sha256').update(Buffer.concat([t, ...hex.map((h) => Buffer.from(h, 'hex'))])).digest('hex');
  };
  const s = '42'.repeat(32);
  const identity = H('veilcore:v1:commit', s);
  const keySalt = H('veilcore:v1:keysalt', s);
  const keyBinding = H('veilcore:v1:keybind', identity, keySalt);
  assert.deepEqual(await node.bindingForSecret(s), { identity, keySalt, keyBinding });
  assert.equal(await node.keyBoundFingerprint(keyBinding, s), H('veilcore:v1:keyrecord', keyBinding, s));
  assert.equal(node.KEY_BOUND_ALGORITHM, 'sha256/key-bound/v1');
  assert.deepEqual(node.KEY_BINDING_TAGS, {
    commit: 'veilcore:v1:commit',
    keySalt: 'veilcore:v1:keysalt',
    keyBinding: 'veilcore:v1:keybind',
    keyRecord: 'veilcore:v1:keyrecord',
  });
});

const older = V.keyBoundRecords.find((r) => r.fields.keyBinding === undefined);
const bound = V.keyBoundRecords.find((r) => r.fields.keyBinding !== undefined);

test('an older record: the fingerprint is the plain SHA-256 of its canonical fields, as before', async () => {
  const plain = createHash('sha256').update(node.canonicalise(older.fields), 'utf8').digest('hex');
  assert.equal((await node.computeRecordFingerprint(older.fields)).fingerprint, plain);
  assert.equal(await node.sha256Hex(node.canonicalise(older.fields)), older.fingerprint);
  // A keyBinding left undefined is absent, as the canonicaliser omits it.
  assert.equal((await node.computeRecordFingerprint({ ...older.fields, keyBinding: undefined })).fingerprint, older.fingerprint);
});

test('a key swapped or dropped after sealing does not verify', async () => {
  const other = V.keyBoundKeys.find((k) => k.keyBinding !== bound.fields.keyBinding).keyBinding;
  const { keyBinding: _dropped, ...rest } = bound.fields;
  void _dropped;
  for (const fields of [{ ...bound.fields, keyBinding: other }, rest]) {
    const v = await node.verifyRecordFingerprint({ fields, fingerprint: bound.fingerprint });
    assert.equal(v.valid, false);
    assert.equal(v.claimed, bound.fingerprint);
  }
});

test('the algorithm an export names must be the one the fields call for', async () => {
  const v1 = await node.verifyRecordFingerprint({ fields: bound.fields, fingerprint: bound.fingerprint, algorithm: 'sha256/canonical-json/v1' });
  assert.equal(v1.valid, false);
  assert.match(v1.reason, /sha256\/key-bound\/v1/);
  const v2 = await node.verifyRecordFingerprint({ fields: older.fields, fingerprint: older.fingerprint, algorithm: 'sha256/key-bound/v1' });
  assert.equal(v2.valid, false);
  // With no algorithm named, the fields alone decide.
  assert.equal((await node.verifyRecordFingerprint({ fields: older.fields, fingerprint: older.fingerprint })).valid, true);
});

test('the verifiers refuse malformed input rather than throw', async () => {
  for (const bad of [null, 5, 'x', [], { fields: [], fingerprint: bound.fingerprint }, { fields: bound.fields, fingerprint: bound.fingerprint.toUpperCase() }, { fields: bound.fields }]) {
    const v = await node.verifyRecordFingerprint(bad);
    assert.equal(v.valid, false, JSON.stringify(bad));
  }
  const c = V.keyBoundChecks.find((x) => x.matches);
  const rec = { fingerprint: c.fingerprint, keySalt: c.keySalt, contentHash: c.contentHash };
  for (const [identity, r] of [[c.identity, null], [c.identity, {}], [42, rec], [undefined, rec], [c.identity, { ...rec, contentHash: `0x${c.contentHash.slice(2)}` }]]) {
    assert.equal(await node.keyMatchesRecord(identity, r), false);
  }
  for (const bad of [c.identity.toUpperCase(), c.identity.slice(2), 7, undefined]) {
    await assert.rejects(() => node.identityFromSecret(bad), /64 lowercase hex/);
    await assert.rejects(() => node.keyBindingOf(bad, c.keySalt), /64 lowercase hex/);
  }
  await assert.rejects(() => node.computeRecordFingerprint([]), /JSON object/);
  await assert.rejects(() => node.computeRecordFingerprint(null), /JSON object/);
});

// The Python implementation, through the same ops the language-agnostic runner uses.
let python = true;
try { execFileSync('python3', ['-c', 'import hashlib, json'], { stdio: 'ignore' }); } catch { python = false; }
const py = (op, input) => {
  try {
    return { ok: JSON.parse(execFileSync('python3', ['-I', here('../conformance/impl.py')], { input: JSON.stringify({ op, input }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })).result };
  } catch (e) {
    return { refused: String(e.stderr ?? e.message) };
  }
};
test('python: every key-bound vector', { skip: !python && 'python3 not installed' }, () => {
  for (const k of V.keyBoundKeys) {
    assert.deepEqual(py('keyFromSecret', { recordSecret: k.recordSecret }).ok, { identity: k.identity, keySalt: k.keySalt, keyBinding: k.keyBinding });
  }
  for (const r of V.keyBoundRecords) {
    assert.equal(py('canonicalise', r.fields).ok, r.canonical, r.name);
    assert.deepEqual(py('recordFingerprint', r.fields).ok, { algorithm: r.algorithm, contentHash: r.contentHash, fingerprint: r.fingerprint }, r.name);
  }
  for (const c of V.keyBoundChecks) {
    assert.equal(py('keyMatch', { identity: c.identity, fingerprint: c.fingerprint, keySalt: c.keySalt, contentHash: c.contentHash }).ok, c.matches, c.name);
  }
  for (const r of V.keyBoundRefusals) {
    const out = py('recordFingerprint', r.fields);
    assert.equal(out.ok, undefined, r.name);
    assert.match(out.refused, REFUSED, r.name);
  }
});
