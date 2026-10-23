// `veilcore backup <file>`: a VeilCore web app backup opened and checked with nothing from
// VeilCore (bin/veilcore.mjs). The records and proofs here are this package's own vectors.
// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { webcrypto } from 'node:crypto';
import { buildBatch } from 'veilcore-records';

const BIN = new URL('../bin/veilcore.mjs', import.meta.url).pathname;
const V = JSON.parse(await readFile(new URL('../conformance/vectors.json', import.meta.url), 'utf8'));

const run = (args, env = {}) =>
  new Promise((resolve) =>
    execFile(process.execPath, [BIN, ...args], { env: { ...process.env, ...env } }, (err, stdout, stderr) =>
      resolve({ code: err ? err.code : 0, stdout, stderr })),
  );

/** A backup as the web app saves it, from the key-bound and animal vectors. */
const backupFile = async () => {
  const plant = V.keyBoundRecords.find((r) => r.fields.keyBinding);
  const animal = V.animalRecords[0];
  const batch = await buildBatch([plant.fingerprint, animal.fingerprint, 'ab'.repeat(32)], 'B-20261023-TEST');
  const proof = {
    ...batch.proofs[plant.fingerprint],
    anchor: { chain: 'midnight', network: 'mainnet', txHash: 'c3'.repeat(32), blockHeight: 4243 },
  };
  return {
    format: 'veilcore-backup',
    version: 3,
    savedAt: '2026-10-23T12:00:00.000Z',
    holderKey: '11'.repeat(32),
    records: [{ recordId: 'VEIL-PLANT', recordSecret: '22'.repeat(32) }],
    recordData: [
      { id: 'VEIL-PLANT', recordFingerprint: plant.fingerprint },
      { id: 'VEIL-ANIMAL', recordFingerprint: animal.fingerprint },
    ],
    proofs: { [plant.fingerprint]: proof },
    sealedFields: { 'VEIL-PLANT': plant.fields, 'VEIL-ANIMAL': animal.fields },
  };
};

const write = async (obj) => {
  const dir = await mkdtemp(join(tmpdir(), 'vc-backup-'));
  const path = join(dir, 'backup.json');
  await writeFile(path, JSON.stringify(obj));
  return { dir, path };
};

test('every record checks out: fingerprint, proof, and the transaction to look up; keys never printed', async () => {
  const f = await backupFile();
  const { dir, path } = await write(f);
  const r = await run(['backup', path, '--out', join(dir, 'out')]);
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /All 2 records check out\./);
  assert.match(r.stdout, /B-20261023-TEST: the proof folds to root/);
  assert.match(r.stdout, new RegExp(`midnight mainnet, transaction ${'c3'.repeat(32)}, block 4243`));
  assert.match(r.stdout, /not batched when this backup was saved/); // the animal: no proof in the file
  assert.ok(!r.stdout.includes('22'.repeat(32)) && !r.stdout.includes('11'.repeat(32)), 'no key is printed');
  const written = JSON.parse(await readFile(join(dir, 'out', 'VEIL-PLANT', 'sealed-fields.json'), 'utf8'));
  assert.deepEqual(written, f.sealedFields['VEIL-PLANT']);
});

test('a record edited after sealing, or a proof for another record, fails (exit 1)', async () => {
  const f = await backupFile();
  f.sealedFields['VEIL-PLANT'] = { ...f.sealedFields['VEIL-PLANT'], notes: 'edited' };
  const a = await run(['backup', (await write(f)).path]);
  assert.equal(a.code, 1);
  assert.match(a.stdout, /DOES NOT MATCH the record/);

  const g = await backupFile();
  const fp = g.recordData[0].recordFingerprint;
  g.proofs[fp] = { ...g.proofs[fp], root: 'ff'.repeat(32) };
  const b = await run(['backup', (await write(g)).path]);
  assert.equal(b.code, 1);
  assert.match(b.stdout, /PROOF DOES NOT FOLD/);
});

test('a file saved before records were carried says so', async () => {
  const f = await backupFile();
  delete f.sealedFields;
  const r = await run(['backup', (await write(f)).path]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /keys but no record contents/);
});

test('a password-locked file opens with its password, and a wrong one opens nothing', async () => {
  const inner = await backupFile();
  const subtle = webcrypto.subtle;
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const base = await subtle.importKey('raw', new TextEncoder().encode('correct horse'), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000 }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('veilcore:backup:v4') }, key, new TextEncoder().encode(JSON.stringify(inner))));
  const b = (u) => Buffer.from(u).toString('base64url');
  const locked = {
    format: 'veilcore-backup', version: 4, savedAt: inner.savedAt,
    locked: { kdf: 'PBKDF2-SHA256', iterations: 600_000, salt: b(salt), alg: 'A256GCM', iv: b(iv), ct: b(ct) },
  };
  const { path } = await write(locked);
  const ok = await run(['backup', path], { VEILCORE_BACKUP_PASSWORD: 'correct horse' });
  assert.equal(ok.code, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /All 2 records check out\./);
  const wrong = await run(['backup', path], { VEILCORE_BACKUP_PASSWORD: 'wrong' });
  assert.equal(wrong.code, 1);
  assert.match(wrong.stderr, /wrong password/);
});
