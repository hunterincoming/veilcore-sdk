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
// An implementation refuses an invalid record either by writing {"error":"..."} (or
// {"rejected":true}) or by exiting non-zero. Both are idiomatic - a Python raise and a
// Rust Err both end up somewhere in that space - and both count.
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

// Three outcomes, not two. Until August 2026 this collapsed to one string, so an
// implementation that produced no output at all was indistinguishable from one that
// refused - and therefore passed every rejection vector. A suite that scores silence as
// a refusal cannot tell a correct implementation from a missing one.
//
//   ok       the implementation answered, and this is its answer
//   refused  the implementation said no, deliberately
//   broken   the implementation did not run, or answered with something unreadable
const ask = (op, input) =>
  new Promise((resolve) => {
    const [bin, ...args] = cmd.split(' ');
    const p = spawn(bin, args, { cwd: fileURLToPath(new URL('..', import.meta.url)) });
    let out = '';
    let err = '';

    p.on('error', (e) => resolve({ kind: 'broken', why: `could not start: ${e.message}` }));
p.stdin.on('error', () => {});
p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));

    p.on('close', (code) => {
      const trimmed = out.trim();

      if (trimmed) {
        let parsed;
        try {
          parsed = JSON.parse(trimmed);
        } catch {
          return resolve({ kind: 'broken', why: `output was not JSON: ${trimmed.slice(0, 120)}` });
        }
        if (parsed.error !== undefined || parsed.rejected === true) {
          return resolve({ kind: 'refused', why: String(parsed.error ?? 'rejected') });
        }
        if (parsed.result !== undefined) {
          return resolve({ kind: 'ok', value: parsed.result });
        }
        return resolve({ kind: 'broken', why: `no result or error field: ${trimmed.slice(0, 120)}` });
      }

      // No stdout. A non-zero exit with a diagnostic on stderr is a refusal - that is
      // what an uncaught Python exception or a Rust panic looks like from out here.
      // A non-zero exit with nothing at all is a process that fell over.
      if (code !== 0 && err.trim()) {
        return resolve({ kind: 'refused', why: err.trim().split('\n').pop() });
      }
      resolve({ kind: 'broken', why: `no output, exit code ${code}` });
    });

    p.stdin.write(JSON.stringify({ op, input }));
    p.stdin.end();
  });

console.log(`VeilCore conformance — format ${vectors.formatVersion}`);
console.log(`implementation: ${cmd}\n`);

// Preflight. Ask for something trivial that every conformant implementation answers, and
// stop if it cannot. Without this, a command that does not exist scores full marks on
// rejections and reports itself partially conformant.
const preflight = await ask('canonicalise', { a: 1 });
if (preflight.kind !== 'ok' || preflight.value !== '{"a":1}') {
  console.error('Preflight failed. The implementation did not answer a trivial input.');
  console.error(`  expected: {"a":1}`);
  console.error(`  got:      ${preflight.kind}${preflight.why ? ` — ${preflight.why}` : ''}` +
                `${preflight.value !== undefined ? ` (${JSON.stringify(preflight.value)})` : ''}`);
  console.error('\nNothing was tested. Fix the command or the implementation and run again.');
  process.exit(2);
}
console.log('Preflight OK\n');

let pass = 0;
const failures = [];

console.log('Canonicalisation');
for (const v of vectors.canonicalisation) {
  const r = await ask('canonicalise', v.input);
  const ok = r.kind === 'ok' && r.value === v.expected;
  ok ? pass++ : failures.push({
    name: v.name,
    expected: v.expected,
    actual: r.kind === 'ok' ? r.value : `${r.kind} — ${r.why}`,
  });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${v.name}`);
}

console.log('\nCommitments');
for (const v of vectors.commitments) {
  const r = await ask('commit', v.record);
  const ok = r.kind === 'ok' && r.value === v.expectedCommitment;
  ok ? pass++ : failures.push({
    name: v.name,
    expected: v.expectedCommitment,
    actual: r.kind === 'ok' ? r.value : `${r.kind} — ${r.why}`,
  });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${v.name}`);
}

// Rejections. Until August 2026 the suite only tested agreement on VALID input, which
// is why three implementations could pass everything while disagreeing about nulls, key
// collisions and non-finite numbers. An implementation must refuse these, not resolve
// them: an implementation that resolves them has chosen how, and two implementations
// choose differently.
//
// Only `refused` passes here. `broken` fails, because an implementation that crashed and
// one that declined are not the same thing, and scoring them alike is how a panic on the
// validation path survived review.
console.log('\nRejections');
for (const v of vectors.rejections ?? []) {
  const input = v.construct === 'non-finite' ? { n: 1e999 } : v.input;
  const r = await ask('canonicalise', input);
  const ok = r.kind === 'refused';
  ok ? pass++ : failures.push({
    name: v.name,
    expected: `refused — ${v.reason}`,
    actual: r.kind === 'ok'
      ? `accepted, returned ${JSON.stringify(r.value)}`
      : `${r.kind} — ${r.why}`,
  });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${v.name}`);
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
