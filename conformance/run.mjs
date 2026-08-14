// Conformance runner.
//
// Point this at any implementation of the VeilCore record format and it reports whether
// that implementation is conformant. Certification is impossible without it — you
// cannot certify conformance you cannot test.
//
//   node conformance/run.mjs                    test the reference implementation
//   node conformance/run.mjs ./path/to/impl.mjs test another implementation
//
// An implementation must export `canonicalise(value)` and `computeCommitment(record)`.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';

const target = process.argv[2] ?? '../dist/index.js';
const impl = await import(target.startsWith('.') ? new URL(target, import.meta.url).href : target);
const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));

let pass = 0;
let fail = 0;
const failures = [];

const check = (section, name, expected, actual) => {
  if (expected === actual) { pass++; return; }
  fail++;
  failures.push({ section, name, expected, actual });
};

console.log(`VeilCore conformance — format ${vectors.formatVersion}`);
console.log(`target: ${target}\n`);

if (typeof impl.canonicalise !== 'function') {
  console.error('FAIL: implementation does not export canonicalise()');
  process.exit(1);
}
if (typeof impl.computeCommitment !== 'function') {
  console.error('FAIL: implementation does not export computeCommitment()');
  process.exit(1);
}

console.log('Canonicalisation');
for (const v of vectors.canonicalisation) {
  let actual;
  try { actual = impl.canonicalise(v.input); } catch (e) { actual = `threw: ${e.message}`; }
  check('canonicalisation', v.name, v.expected, actual);
  console.log(`  ${v.expected === actual ? 'PASS' : 'FAIL'}  ${v.name}`);
}

console.log('\nCommitments');
for (const v of vectors.commitments) {
  let actual;
  try { actual = await impl.computeCommitment(v.record); } catch (e) { actual = `threw: ${e.message}`; }
  check('commitment', v.name, v.expectedCommitment, actual);
  console.log(`  ${v.expectedCommitment === actual ? 'PASS' : 'FAIL'}  ${v.name}`);
}

// Rejections. A suite that only tests valid input cannot catch two implementations
// disagreeing about what is INVALID, which is where every divergence found in the
// August 2026 external review actually lived.
for (const v of vectors.rejections ?? []) {
  const input = v.construct === 'non-finite' ? { n: Infinity } : v.input;
  let rejected = false;
  try {
    canonicalise(input);
  } catch {
    rejected = true;
  }
  check('rejections', v.name, 'rejected', rejected ? 'rejected' : 'accepted');
}

console.log(`\n${pass} passed, ${fail} failed`);

if (fail > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`\n  ${f.section} — ${f.name}`);
    console.log(`    expected: ${f.expected}`);
    console.log(`    actual:   ${f.actual}`);
  }
  console.log('\nNot conformant.');
  process.exit(1);
}

console.log('\nConformant.');
