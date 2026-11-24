// Evidence packages: built by the SDK, checked by the bundled verify.py with nothing but
// Python's standard library, and by the TypeScript checker. Tampering with any file fails.
// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { computeCommitment, buildBatch, buildEvidencePackage, verifyEvidencePackage, COMMITMENT_ALGORITHM } from '../dist/index.js';

const record = async (id) => {
  const r = {
    formatVersion: '0.1', recordId: id, subjectType: 'plant-variety', profile: 'veilcore/profile/plant-variety/v1',
    commitment: '', commitmentAlgorithm: COMMITMENT_ALGORITHM,
    anchor: { chain: 'midnight', network: 'preprod' }, sealedAt: '2026-10-03T12:00:00Z',
    holder: { id: 'vc_hld_test' }, parents: [], attestations: [],
    profileData: { denomination: 'Harbour Mist', nonce: createHash('sha256').update(id).digest('hex') },
  };
  r.commitment = await computeCommitment(r);
  return r;
};

const write = (files) => {
  const dir = mkdtempSync(join(tmpdir(), 'vc-evidence-'));
  for (const [n, b] of Object.entries(files)) writeFileSync(join(dir, n), b);
  return dir;
};
const runPy = (dir) => spawnSync('python3', [join(dir, 'verify.py')], { encoding: 'utf8' });

const setup = async () => {
  const recs = await Promise.all(['a', 'b', 'c'].map((x) => record(`vc_rec_ev_${x}`)));
  const batch = await buildBatch(recs.map((r) => r.commitment), 'B-TEST', '2026-10-03T12:05:00Z');
  const proof = { ...batch.proofs[recs[1].commitment], anchor: { chain: 'midnight', network: 'preprod', txHash: 'ab'.repeat(32), blockHeight: 2808047 } };
  const rootBin = Buffer.from(batch.root, 'hex');
  const header = Buffer.concat([Buffer.from('\x00OpenTimestamps\x00\x00Proof\x00', 'latin1'), Buffer.from([0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94])]);
  const ots = Buffer.concat([header, Buffer.from([0x01, 0x08]), createHash('sha256').update(rootBin).digest(), Buffer.from([0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e, 0x00])]);
  return { rec: recs[1], proof, rootBin, ots };
};

test('a package passes its own verify.py with plain Python, and the TypeScript checker', async () => {
  const { rec, proof, rootBin, ots } = await setup();
  const files = await buildEvidencePackage({ record: rec, proof, opentimestamps: { rootBin, ots }, generatedAt: '2026-10-03T13:00:00Z' });
  assert.deepEqual(Object.keys(files).sort(), ['DECLARATION-TEMPLATE.txt', 'MANIFEST.json', 'README.txt', 'inclusion-proof.json', 'record.json', 'root.bin', 'root.bin.ots', 'verify.py']);
  const dir = write(files);
  const r = runPy(dir);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /the record is exactly as it was when sealed/);
  assert.match(r.stdout, /root\.bin\.ots is an OpenTimestamps proof for root\.bin/);
  assert.match(r.stdout, /confirm transaction abab/);
  assert.match(r.stdout, /every offline check passed/);
  const ts = await verifyEvidencePackage(files);
  assert.equal(ts.ok, true, JSON.stringify(ts.checks));
  assert.match(new TextDecoder().decode(files['README.txt']), /does not establish/i);
  assert.match(new TextDecoder().decode(files['README.txt']), /TEST NETWORK: the ledger anchor is on midnight preprod/);
});

test('changing any byte of the record is caught by both checkers', async () => {
  const { rec, proof } = await setup();
  const files = await buildEvidencePackage({ record: rec, proof });
  const tampered = JSON.parse(new TextDecoder().decode(files['record.json']));
  tampered.profileData.denomination = 'Harbour Mist 2';
  files['record.json'] = new TextEncoder().encode(JSON.stringify(tampered, null, 2) + '\n');
  const dir = write(files);
  const r = runPy(dir);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /record\.json has changed/);
  assert.match(r.stdout, /SOME CHECKS FAILED/);
  assert.equal((await verifyEvidencePackage(files)).ok, false);
});

test('a forged manifest does not save a tampered record: the commitment still fails', async () => {
  const { rec, proof } = await setup();
  const files = await buildEvidencePackage({ record: rec, proof });
  const tampered = JSON.parse(new TextDecoder().decode(files['record.json']));
  tampered.sealedAt = '2020-01-01T00:00:00Z'; // backdating
  files['record.json'] = new TextEncoder().encode(JSON.stringify(tampered, null, 2) + '\n');
  const m = JSON.parse(new TextDecoder().decode(files['MANIFEST.json']));
  m.files['record.json'] = createHash('sha256').update(files['record.json']).digest('hex');
  files['MANIFEST.json'] = new TextEncoder().encode(JSON.stringify(m));
  const r = runPy(write(files));
  assert.equal(r.status, 1);
  assert.match(r.stdout, /but the record states/);
});

test('a package is refused for a record that does not match itself or its proof', async () => {
  const { rec, proof } = await setup();
  await assert.rejects(buildEvidencePackage({ record: { ...rec, commitment: '00'.repeat(32) } }), /does not match its own commitment/);
  const other = await record('vc_rec_ev_other');
  await assert.rejects(buildEvidencePackage({ record: other, proof }), /different record/);
});

test('verify.py is the conformance-tested implementation, unchanged', () => {
  const impl = readFileSync(new URL('../conformance/impl.py', import.meta.url), 'utf8');
  const bundled = readFileSync(new URL('../src/evidence-verifier.generated.ts', import.meta.url), 'utf8');
  const py = JSON.parse(bundled.slice(bundled.indexOf('= ') + 2, bundled.lastIndexOf(';')));
  const body = impl.replace(/\nif __name__ == "__main__":\n    main\(\)\n?$/, '\n');
  assert.ok(py.startsWith(body), 'verify.py starts with conformance/impl.py exactly');
  void execFileSync;
});

// ── RFC 3161 tokens in a package (fixtures from test/fixtures/rfc3161, TEST-ONLY keys)

const fx = (p) => new URL(`./fixtures/rfc3161/${p}`, import.meta.url);
const hasOpenssl = spawnSync('openssl', ['ts', '-help'], { encoding: 'utf8' }).status === 0;
const tsaPackage = async (recordToken) => {
  const rec = JSON.parse(readFileSync(fx('record.json'), 'utf8'));
  rec.anchor = [
    { chain: 'midnight', network: 'undeployed' },
    { kind: 'rfc3161', chain: 'n/a', network: 'n/a', tsa: 'TEST TSA tsa-p256', token: readFileSync(fx(recordToken)).toString('base64') },
  ];
  const proof = JSON.parse(readFileSync(fx('proof.json'), 'utf8'));
  proof.anchor = { kind: 'rfc3161', chain: 'n/a', network: 'n/a', token: readFileSync(fx('tokens/batch-p256.tst')).toString('base64') };
  return buildEvidencePackage({ record: rec, proof, generatedAt: '2026-10-03T13:00:00Z' });
};

test('RFC 3161 tokens are carried, checked by TypeScript, and handed to openssl by verify.py', async () => {
  // The record's token is given as a full TimeStampResp; the package carries the token alone.
  const files = await tsaPackage('tokens/rsa-sha256.tsr');
  assert.deepEqual(files['rfc3161-record-1.tst'], new Uint8Array(readFileSync(fx('tokens/rsa-sha256.tst'))));
  assert.ok(files['rfc3161-batch.tst'] && files['commitment.bin'] && files['root.bin']);
  const ts = await verifyEvidencePackage(files);
  assert.equal(ts.ok, true, JSON.stringify(ts.checks.filter((c) => !c.ok)));
  assert.ok(ts.checks.some((c) => c.ok && /^rfc3161-record-1\.tst: the imprint is the SHA-256/.test(c.what)));
  assert.ok(ts.checks.some((c) => c.ok && /^rfc3161-batch\.tst: the TSA states 20/.test(c.what)));
  assert.ok(ts.notChecked.includes('rfc3161-record-1.tst: certificate chain to a trusted root'));

  const dir = write(files);
  const r = runPy(dir);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /rfc3161-record-1\.tst is the RFC 3161 token the record states, over commitment\.bin/);
  assert.match(r.stdout, /rfc3161-batch\.tst is the RFC 3161 token the inclusion proof states, over root\.bin/);
  const commands = [...r.stdout.matchAll(/openssl ts -verify .*$/gm)].map((m) => m[0]);
  assert.deepEqual(commands, [
    'openssl ts -verify -data commitment.bin -in rfc3161-record-1.tst -token_in -CAfile TSA-ROOT.pem',
    'openssl ts -verify -data root.bin -in rfc3161-batch.tst -token_in -CAfile TSA-ROOT.pem',
  ]);
  if (hasOpenssl) {
    // The printed commands work, given the (test) TSA root.
    writeFileSync(join(dir, 'TSA-ROOT.pem'), readFileSync(fx('certs/ca.pem')));
    for (const c of commands) {
      const o = spawnSync('sh', ['-c', c], { cwd: dir, encoding: 'utf8' });
      assert.equal(o.status, 0, c + '\n' + o.stdout + o.stderr);
      assert.match(o.stdout, /Verification: OK/);
    }
  }
});

test('a token over the wrong bytes fails the TypeScript check, and the openssl command verify.py prints', async () => {
  // The batch token stated as if it stamped the record.
  const files = await tsaPackage('tokens/batch-p256.tst');
  const ts = await verifyEvidencePackage(files);
  assert.equal(ts.ok, false);
  assert.ok(ts.checks.some((c) => !c.ok && /^rfc3161-record-1\.tst: the imprint/.test(c.what)));
  const dir = write(files);
  const r = runPy(dir);
  assert.match(r.stdout, /to do\] verify its signature and imprint/, 'Python lists it as to do, and cannot catch it');
  if (hasOpenssl) {
    writeFileSync(join(dir, 'TSA-ROOT.pem'), readFileSync(fx('certs/ca.pem')));
    const o = spawnSync('sh', ['-c', 'openssl ts -verify -data commitment.bin -in rfc3161-record-1.tst -token_in -CAfile TSA-ROOT.pem'], { cwd: dir, encoding: 'utf8' });
    assert.notEqual(o.status, 0);
  }
});

// ── Several contracts (SPEC 9.2.1 and 9.4): verify.py names the contract a ledger anchor's
// transaction must have called, from the pinned list it carries, and dates nothing on any other.

const pinnedInVerifyPy = (py) => {
  const dir = write({ 'verify.py': py });
  const out = execFileSync('python3', ['-I', '-c', 'import json,runpy,sys; print(json.dumps(runpy.run_path(sys.argv[1], run_name="pinned")["_PINNED_CONTRACTS"]))', join(dir, 'verify.py')], { encoding: 'utf8' });
  return JSON.parse(out);
};
const bundledPy = () => {
  const bundled = readFileSync(new URL('../src/evidence-verifier.generated.ts', import.meta.url), 'utf8');
  return JSON.parse(bundled.slice(bundled.indexOf('= ') + 2, bundled.lastIndexOf(';')));
};
const V1_MAIN = 'a04de0a2684f3713276325649540c7278ffd07cba8b014e7489844f319a02347';
const V1_CLAIMS = 'ef763eb4ad1846b716dbfa90c00560a9a943ffb4d1fc638b0707df5adefd070d';

test("verify.py's mainnet main contracts are SPEC 9.2.1's rows, and its list is well formed", () => {
  const pinned = pinnedInVerifyPy(bundledPy());
  const spec = readFileSync(new URL('../SPEC.md', import.meta.url), 'utf8');
  const section = spec.slice(spec.indexOf('### 9.2.1'), spec.indexOf('### 9.3'));
  const rows = [...section.matchAll(/^\| v(\d+) \| Midnight mainnet[^|]*\| `([0-9a-f]{64})` \|/gm)].map((m) => ({ address: m[2], version: Number(m[1]) }));
  assert.ok(rows.length >= 1, 'SPEC 9.2.1 lists at least version 1');
  const main = pinned.mainnet.filter((c) => c.kind === 'main').map((c) => ({ address: c.address, version: c.version }));
  const byAddress = (a, b) => a.address.localeCompare(b.address);
  assert.deepEqual(main.sort(byAddress), rows.sort(byAddress));
  assert.deepEqual(Object.keys(pinned).sort(), ['mainnet', 'preprod']);
  for (const list of Object.values(pinned)) {
    assert.ok(list.some((c) => c.kind === 'main'));
    for (const c of list) {
      assert.match(c.address, /^[0-9a-f]{64}$/);
      assert.ok(c.kind === 'main' || c.kind === 'claims');
      assert.ok(Number.isSafeInteger(c.version) && c.version >= 1);
    }
    assert.equal(new Set(list.map((c) => c.address)).size, list.length);
  }
});

/** A package whose inclusion proof's anchor is `anchor`, checked by its verify.py (or by `py`). */
const anchoredOn = async (anchor, py) => {
  const { rec, proof } = await setup();
  const files = await buildEvidencePackage({ record: rec, proof: { ...proof, anchor: { chain: 'midnight', txHash: 'ab'.repeat(32), ...anchor } } });
  if (py !== undefined) {
    // A copy with another pinned list: its manifest line is rewritten to match, as a release would.
    files['verify.py'] = new TextEncoder().encode(py);
    const m = JSON.parse(new TextDecoder().decode(files['MANIFEST.json']));
    m.files['verify.py'] = createHash('sha256').update(files['verify.py']).digest('hex');
    files['MANIFEST.json'] = new TextEncoder().encode(JSON.stringify(m, null, 2) + '\n');
  }
  return runPy(write(files));
};

test('verify.py: on mainnet, the pinned version 1 contract is named with the whole list', async () => {
  const r = await anchoredOn({ network: 'mainnet', contractAddress: V1_MAIN });
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.stdout, new RegExp(`called VeilCore contract version 1 \\(${V1_MAIN}\\) and no other VeilCore contract`));
  assert.match(r.stdout, new RegExp(`${V1_CLAIMS} \\(version 1, claims\\)`));
  assert.doesNotMatch(r.stdout, /version 2/);
});

test('verify.py: a contract not on the list, the claims contract, or an address not in lowercase hex dates nothing', async () => {
  for (const contractAddress of ['cd'.repeat(32), V1_CLAIMS, V1_MAIN.toUpperCase(), `0x${V1_MAIN}`, 42]) {
    const r = await anchoredOn({ network: 'mainnet', contractAddress });
    assert.equal(r.status, 1, `${contractAddress}: ${r.stdout}`);
    assert.match(r.stdout, /\[FAIL\] transaction abab.*dates nothing/);
    assert.doesNotMatch(r.stdout, /confirm transaction/);
  }
  // Preprod is judged by preprod's own list.
  const pre = await anchoredOn({ network: 'preprod', contractAddress: V1_MAIN });
  assert.equal(pre.status, 1);
  const ok = await anchoredOn({ network: 'preprod', contractAddress: '72fe33436d424fcf247919c8e2f0de224175cc55061739be0ebffb2d650f2f73' });
  assert.equal(ok.status, 0, ok.stdout);
});

test('verify.py: no contract named, every pinned main contract is a candidate; a network with no list reads as before', async () => {
  const r = await anchoredOn({ network: 'mainnet' });
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.stdout, /called one of VeilCore's main contracts and no other VeilCore contract/);
  const local = await anchoredOn({ network: 'undeployed', contractAddress: 'cd'.repeat(32) });
  assert.equal(local.status, 0, local.stdout);
  assert.match(local.stdout, /confirm transaction abab\S* on midnight \(undeployed\) published the batch root/);
});

test('verify.py with version 2 pinned (a copy of its list with v2 added): named by its entry, with its status', async () => {
  const V2 = 'f2'.repeat(32);
  const py = bundledPy().replace(
    `        {"address": "${V1_CLAIMS}", "kind": "claims", "version": 1},\n`,
    `        {"address": "${V1_CLAIMS}", "kind": "claims", "version": 1},\n        {"address": "${V2}", "kind": "main", "version": 2},\n`,
  );
  assert.notEqual(py, bundledPy());
  assert.equal(pinnedInVerifyPy(py).mainnet.length, 3);
  const r = await anchoredOn({ network: 'mainnet', contractAddress: V2 }, py);
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.stdout, new RegExp(`called VeilCore contract version 2 \\(${V2}\\) and no other VeilCore contract`));
  assert.match(r.stdout, /deployed on mainnet for testing by VeilCore\. It is not yet independently reviewed and not for your records\./);
  // Version 1 is unchanged, with version 2 on the list it must not also have called.
  const v1 = await anchoredOn({ network: 'mainnet', contractAddress: V1_MAIN }, py);
  assert.equal(v1.status, 0, v1.stdout);
  assert.match(v1.stdout, new RegExp(`${V2} \\(version 2\\)`));
  assert.doesNotMatch(v1.stdout, /for testing by VeilCore/);
  // No contract named: version 2 is a candidate, and said to be one.
  assert.match((await anchoredOn({ network: 'mainnet' }, py)).stdout, /If it called version 2: VeilCore contract version 2 is deployed/);
});
