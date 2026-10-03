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
