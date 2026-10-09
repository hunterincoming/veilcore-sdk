// A report paired with a ledger identity (SPEC 3.7).
//
// The binding is plain SHA-256 over four 32-byte elements, the same in a browser and in
// Node, and it changes with every input: a binding made for one identity is not one for
// any other.
import { test } from 'node:test';
import assert from 'node:assert';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as node from '../dist/index.js';
import * as browser from '../dist/index.browser.js';

const R = '18bc28bc2feb83c05c28cc04bdda0aab7d88f668c329f7c8ae19574a79c67e8e';
const I = '80ffc834e847d281ceba9a196e5643e68bbd9951b81cc81892035b5bd748930b';
const S = '1c2a98a182af6fee2dece33938396d45bd76b72c869ef8f4af6b8af975be02b1';

test('is SHA-256 over the padded tag and the three inputs, in that order', async () => {
  const tag = Buffer.alloc(32);
  tag.write('veilcore:v1:dnapair', 'utf8');
  const plain = createHash('sha256')
    .update(Buffer.concat([tag, Buffer.from(R, 'hex'), Buffer.from(I, 'hex'), Buffer.from(S, 'hex')]))
    .digest('hex');
  assert.equal(await node.dnaPairBinding(R, I, S), plain);
  assert.equal(await browser.dnaPairBinding(R, I, S), plain);
  assert.equal(node.DNA_PAIR_TAG, 'veilcore:v1:dnapair');
});

test('matches the published vector', async () => {
  const v = JSON.parse(readFileSync(new URL('../conformance/vectors.json', import.meta.url), 'utf8')).pairings[0];
  assert.equal(await node.dnaPairBinding(v.input.reportHash, v.input.identity, v.input.salt), v.expected);
});

test('another identity, salt or report gives another binding', async () => {
  const b = await node.dnaPairBinding(R, I, S);
  assert.notEqual(await node.dnaPairBinding(R, S, S), b);
  assert.notEqual(await node.dnaPairBinding(R, I, I), b);
  assert.notEqual(await node.dnaPairBinding(I, I, S), b);
});

test('refuses anything but 64 lowercase hex characters', async () => {
  for (const bad of [R.toUpperCase(), R.slice(2), `0x${R.slice(2)}`, 42, undefined])
    await assert.rejects(() => node.dnaPairBinding(bad, I, S), /64 lowercase hex/);
});
