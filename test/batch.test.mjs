// Batch inclusion proofs.
//
// A proof that verifies when it should is the easy half. The half that matters is a
// proof that fails when the record was not in the batch — otherwise the whole thing
// proves nothing.
import { test } from 'node:test';
import assert from 'node:assert';
import { buildBatch, verifyInclusion } from '../dist/index.js';

const commits = Array.from({ length: 7 }, (_, i) => `${i}`.repeat(64));

test('every commitment in a batch has a valid proof', async () => {
  const batch = await buildBatch(commits, 'B-001');
  for (const c of commits) {
    assert.ok(await verifyInclusion(batch.proofs[c]), `proof failed for ${c.slice(0, 8)}`);
  }
});

test('a commitment not in the batch cannot be proven', async () => {
  const batch = await buildBatch(commits, 'B-001');
  const forged = { ...batch.proofs[commits[0]], commitment: 'f'.repeat(64) };
  assert.equal(await verifyInclusion(forged), false);
});

test('a tampered path fails', async () => {
  const batch = await buildBatch(commits, 'B-001');
  const p = batch.proofs[commits[3]];
  const tampered = { ...p, path: p.path.map((s, i) => (i === 0 ? { ...s, sibling: 'a'.repeat(64) } : s)) };
  assert.equal(await verifyInclusion(tampered), false);
});

test('a flipped direction bit fails', async () => {
  const batch = await buildBatch(commits, 'B-001');
  const p = batch.proofs[commits[2]];
  if (p.path.length === 0) return;
  const flipped = { ...p, path: p.path.map((s, i) => (i === 0 ? { ...s, siblingIsLeft: !s.siblingIsLeft } : s)) };
  assert.equal(await verifyInclusion(flipped), false);
});

test('the root is independent of insertion order', async () => {
  const a = await buildBatch(commits, 'B-001', '2026-01-01T00:00:00Z');
  const b = await buildBatch([...commits].reverse(), 'B-001', '2026-01-01T00:00:00Z');
  assert.equal(a.root, b.root);
});

test('a different set produces a different root', async () => {
  const a = await buildBatch(commits, 'B-001', '2026-01-01T00:00:00Z');
  const b = await buildBatch([...commits, 'e'.repeat(64)], 'B-001', '2026-01-01T00:00:00Z');
  assert.notEqual(a.root, b.root);
});

test('a single-record batch works', async () => {
  const batch = await buildBatch([commits[0]], 'B-002');
  assert.ok(await verifyInclusion(batch.proofs[commits[0]]));
});

test('duplicates are collapsed, not double-counted', async () => {
  const a = await buildBatch([commits[0], commits[1]], 'B-003', '2026-01-01T00:00:00Z');
  const b = await buildBatch([commits[0], commits[1], commits[0]], 'B-003', '2026-01-01T00:00:00Z');
  assert.equal(a.root, b.root);
});

test('a large batch still proves every member', async () => {
  const many = Array.from({ length: 500 }, (_, i) => i.toString(16).padStart(64, '0'));
  const batch = await buildBatch(many, 'B-BIG');
  for (const c of [many[0], many[1], many[249], many[499]]) {
    assert.ok(await verifyInclusion(batch.proofs[c]), `failed for ${c.slice(-6)}`);
  }
});

test('an empty batch is refused rather than producing a meaningless root', async () => {
  await assert.rejects(() => buildBatch([], 'B-EMPTY'));
});
