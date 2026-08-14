// Language-agnostic conformance runner.
//
// The claim the format rests on is that any implementation in any language can compute
// a record commitment. That claim is untested while only one implementation exists.
//
// This runner talks to an implementation over stdin/stdout, so it can test Python, Go,
// Rust or anything else. The implementation reads a JSON job on stdin and writes a JSON
// result on stdout:
//
//   in:  {"op":"canonicalise","input":{...}}   out: {"result":"{...}"}
//   in:  {"op":"commit","input":{...}}         out: {"result":"<hex>"}
//
//   node conformance/run-cli.mjs "python3 conformance/impl.py"
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cmd = process.argv[2];
if (!cmd) {
  console.error('usage: node conformance/run-cli.mjs "<command to run the implementation>"');
  process.exit(2);
}

const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));

const ask = (op, input) =>
  new Promise((resolve) => {
    const [bin, ...args] = cmd.split(' ');
    const p = spawn(bin, args, { cwd: fileURLToPath(new URL('..', import.meta.url)) });
    let out = '';
    let err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('close', () => {
      try { resolve(JSON.parse(out).result); }
      catch { resolve(`error: ${err.trim() || out.trim() || 'no output'}`); }
    });
    p.stdin.write(JSON.stringify({ op, input }));
    p.stdin.end();
  });

let pass = 0;
const failures = [];

console.log(`VeilCore conformance — format ${vectors.formatVersion}`);
console.log(`implementation: ${cmd}\n`);

console.log('Canonicalisation');
for (const v of vectors.canonicalisation) {
  const actual = await ask('canonicalise', v.input);
  const ok = actual === v.expected;
  ok ? pass++ : failures.push({ name: v.name, expected: v.expected, actual });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${v.name}`);
}

console.log('\nCommitments');
for (const v of vectors.commitments) {
  const actual = await ask('commit', v.record);
  const ok = actual === v.expectedCommitment;
  ok ? pass++ : failures.push({ name: v.name, expected: v.expectedCommitment, actual });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${v.name}`);
}

// Rejections. Until August 2026 the suite only tested agreement on VALID input, which
// is why three implementations could pass everything while disagreeing about nulls, key
// collisions and non-finite numbers. An implementation must refuse these, not resolve
// them: an implementation that resolves them has chosen how, and two implementations
// choose differently.
console.log('\nRejections');
for (const v of vectors.rejections ?? []) {
  const input = v.construct === 'non-finite' ? { n: 1e999 } : v.input;
  let refused = false;
  let got;
  try {
    got = await ask('canonicalise', input);
    // An implementation may signal refusal by returning an error field rather than
    // exiting non-zero. Both count.
    refused = got === undefined || got === null || String(got).startsWith('error');
  } catch {
    refused = true;
  }
  refused ? pass++ : failures.push({
    name: v.name,
    expected: `rejected — ${v.reason}`,
    actual: `accepted, returned ${JSON.stringify(got)}`,
  });
  console.log(`  ${refused ? 'PASS' : 'FAIL'}  ${v.name}`);
}

console.log(`\n${pass} passed, ${failures.length} failed`);
if (failures.length) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`\n  ${f.name}`);
    console.log(`    expected: ${f.expected}`);
    console.log(`    actual:   ${f.actual}`);
  }
  console.log('\nNot conformant.');
  process.exit(1);
}
console.log('\nConformant.');
