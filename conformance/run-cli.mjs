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
//   in:  {"op":"attestationPayload","input":{...}}  out: {"result":"{...}"}
//   in:  {"op":"commit","input":{...}}         out: {"result":"<hex>"}
//   in:  {"op":"fieldSet","input":{...}}       out: {"result":{"schemaDocumentDigest":"<hex>",
//          "schemaId":"<hex>","slotValues":[...],"salts":[...],"leaves":[...],
//          "setRoot":"<hex>"}}  (keys in this order)
//   in:  {"op":"dnaPair","input":{"reportHash":"<hex>","identity":"<hex>","salt":"<hex>"}}
//                                              out: {"result":"<hex>"}  (SPEC 3.7)
//   in:  {"op":"keyFromSecret","input":{"recordSecret":"<hex>"}}
//          out: {"result":{"identity":"<hex>","keySalt":"<hex>","keyBinding":"<hex>"}}  (SPEC 3.6.1)
//   in:  {"op":"recordFingerprint","input":{...committed fields...}}
//          out: {"result":{"algorithm":"...","contentHash":"<hex>","fingerprint":"<hex>"}}  (SPEC 3.6.1)
//   in:  {"op":"keyMatch","input":{"identity":"<hex>","fingerprint":"<hex>","keySalt":"<hex>","contentHash":"<hex>"}}
//          out: {"result":true|false}  (SPEC 3.6.1; malformed input is false, not an error)
//   (key order inside a result object is free for these three)
//   in:  {"op":"animalFingerprint","input":{...an animal record's committed fields...}}
//          out: as recordFingerprint, or a refusal for fields not in the profile's form
//          (SPEC 11.8, draft). An implementation that doesn't check the animal profile is
//          run with --without-animal-profile, and the result says those refusals were not run.
//   in:  {"op":"strainFingerprint","input":{...a strain record's committed fields...}}
//          out: as recordFingerprint, or refused for fields not in the strain profile's form
//          (SPEC 11.9, draft); --without-strain-profile leaves those refusals out, and says so.
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
// `inputText` is sent as written, not re-serialised: JSON.stringify turns 95.0 into 95
// and Infinity into null, which is exactly the difference some vectors exist to test.
const ask = (op, input, inputText) =>
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

    p.stdin.write(
      inputText !== undefined ? `{"op":${JSON.stringify(op)},"input":${inputText}}` : JSON.stringify({ op, input }),
    );
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
  const r = await ask('canonicalise', v.input, v.inputText);
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
console.log('\nAttestation payloads');
for (const v of vectors.attestations ?? []) {
  const r = await ask('attestationPayload', v.attestation);
  const ok = r.kind === 'ok' && r.value === v.expectedPayload;
  ok ? pass++ : failures.push({
    name: v.name,
    expected: v.expectedPayload,
    actual: r.kind === 'ok' ? r.value : `${r.kind} — ${r.why}`,
  });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${v.name}`);
}

console.log('\nInclusion proofs');
for (const v of vectors.inclusion ?? []) {
  const r = await ask('fold', { commitment: v.commitment, path: v.path });
  const ok = r.kind === 'ok' && r.value === v.expectedRoot;
  ok ? pass++ : failures.push({
    name: v.name,
    expected: v.expectedRoot,
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
  const r = await ask('canonicalise', v.input, v.inputText);
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

// Field sets (SPEC 4.5): sealing 16 typed slot values under a schema.
console.log('\nField sets');
for (const v of vectors.fieldSets ?? []) {
  const r = await ask('fieldSet', v.input);
  const expected = JSON.stringify(v.expected);
  const ok = r.kind === 'ok' && JSON.stringify(r.value) === expected;
  ok ? pass++ : failures.push({ name: v.name, expected, actual: r.kind === 'ok' ? JSON.stringify(r.value) : `${r.kind} — ${r.why}` });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${v.name}`);
}
for (const v of vectors.fieldRejections ?? []) {
  const r = await ask('fieldSet', v.input);
  const ok = r.kind === 'refused';
  ok ? pass++ : failures.push({ name: v.name, expected: `refused — ${v.reason}`, actual: r.kind === 'ok' ? 'accepted' : `${r.kind} — ${r.why}` });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  refuses: ${v.name}`);
}
for (const v of vectors.commitmentRejections ?? []) {
  const r = await ask('commit', v.record);
  const ok = r.kind === 'refused';
  ok ? pass++ : failures.push({ name: v.name, expected: `refused — ${v.reason}`, actual: r.kind === 'ok' ? `accepted, returned ${JSON.stringify(r.value)}` : `${r.kind} — ${r.why}` });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  refuses: ${v.name}`);
}

// Report pairings (SPEC 3.7): the value a ledger pairing publishes for a report.
console.log('\nReport pairings');
for (const v of vectors.pairings ?? []) {
  const r = await ask('dnaPair', v.input);
  const ok = r.kind === 'ok' && r.value === v.expected;
  ok ? pass++ : failures.push({ name: v.name, expected: v.expected, actual: r.kind === 'ok' ? r.value : `${r.kind} — ${r.why}` });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${v.name}`);
}

// Records that name their own key (SPEC 3.6.1).
console.log('\nRecords that name their own key');
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const outcome = (r) => (r.kind === 'ok' ? JSON.stringify(r.value) : `${r.kind} — ${r.why}`);
for (const v of vectors.keyBoundKeys ?? []) {
  const name = `the key from record secret ${v.recordSecret.slice(0, 8)}...`;
  const r = await ask('keyFromSecret', { recordSecret: v.recordSecret });
  const expected = [v.identity, v.keySalt, v.keyBinding];
  const ok = r.kind === 'ok' && r.value !== null && typeof r.value === 'object' && same([r.value.identity, r.value.keySalt, r.value.keyBinding], expected);
  ok ? pass++ : failures.push({ name, expected: JSON.stringify(expected), actual: outcome(r) });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}`);
}
for (const v of vectors.keyBoundRecords ?? []) {
  // The canonical text too: a fingerprint that agrees by accident over different text
  // would not be agreement.
  const c = await ask('canonicalise', v.fields);
  const r = await ask('recordFingerprint', v.fields);
  const expected = [v.canonical, v.algorithm, v.contentHash, v.fingerprint];
  const ok = c.kind === 'ok' && c.value === v.canonical && r.kind === 'ok' && r.value !== null && typeof r.value === 'object' &&
    same([c.value, r.value.algorithm, r.value.contentHash, r.value.fingerprint], expected);
  ok ? pass++ : failures.push({ name: v.name, expected: JSON.stringify(expected), actual: `canonical: ${outcome(c)}; fingerprint: ${outcome(r)}` });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${v.name}`);
}
for (const v of vectors.keyBoundChecks ?? []) {
  const name = `${v.matches ? 'matches' : 'does not match'}: ${v.name}`;
  const r = await ask('keyMatch', { identity: v.identity, fingerprint: v.fingerprint, keySalt: v.keySalt, contentHash: v.contentHash });
  const ok = r.kind === 'ok' && r.value === v.matches;
  ok ? pass++ : failures.push({ name, expected: String(v.matches), actual: outcome(r) });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}`);
}
for (const v of vectors.keyBoundRefusals ?? []) {
  const r = await ask('recordFingerprint', v.fields);
  const ok = r.kind === 'refused';
  ok ? pass++ : failures.push({ name: v.name, expected: 'refused — keyBinding must be 64 lowercase hex characters', actual: r.kind === 'ok' ? `accepted, returned ${JSON.stringify(r.value)}` : `${r.kind} — ${r.why}` });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  refuses: ${v.name}`);
}

// Animal records (SPEC 11.8, draft). Their fingerprints are computed exactly as any record's,
// so every implementation answers them with `recordFingerprint`: agreement there shows the
// profile changed no rule. The profile's own form is checked with `animalFingerprint`, which
// refuses fields not in the profile's form and otherwise answers as `recordFingerprint`. An
// implementation that doesn't offer the profile check is asked once with a valid record; if it
// can't answer, its refusals are never counted as passes (an unknown op looks like a refusal
// from out here). It fails them, or with --without-animal-profile they are left out and the
// result says so.
console.log('\nAnimal records');
const withoutAnimal = process.argv.includes('--without-animal-profile');
for (const v of vectors.animalRecords ?? []) {
  const c = await ask('canonicalise', v.fields);
  const r = await ask('recordFingerprint', v.fields);
  const expected = [v.canonical, v.algorithm, v.contentHash, v.fingerprint];
  const ok = c.kind === 'ok' && c.value === v.canonical && r.kind === 'ok' && r.value !== null && typeof r.value === 'object' &&
    same([c.value, r.value.algorithm, r.value.contentHash, r.value.fingerprint], expected);
  ok ? pass++ : failures.push({ name: v.name, expected: JSON.stringify(expected), actual: `canonical: ${outcome(c)}; fingerprint: ${outcome(r)}` });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${v.name}`);
}
const refusals = vectors.animalRefusals ?? [];
if (refusals.length) {
  const probe = vectors.animalRecords?.[0];
  const p = probe ? await ask('animalFingerprint', probe.fields) : { kind: 'broken', why: 'no animal record to ask with' };
  const offers = p.kind === 'ok' && p.value !== null && typeof p.value === 'object' && p.value.fingerprint === probe.fingerprint;
  if (!offers && withoutAnimal) {
    console.log(`  NOT RUN  ${refusals.length} animal-profile refusals: this implementation does not check the profile (--without-animal-profile)`);
  } else if (!offers) {
    for (const v of refusals) failures.push({ name: `refuses: ${v.name}`, expected: 'refused by animalFingerprint', actual: `the op is not answered for a valid record (${outcome(p)})` });
    console.log(`  FAIL  ${refusals.length} animal-profile refusals: op animalFingerprint is not answered for a valid record (${outcome(p)}). Use --without-animal-profile to leave them out and say so.`);
  } else {
    for (const v of refusals) {
      const r = await ask('animalFingerprint', v.fields);
      const ok = r.kind === 'refused';
      ok ? pass++ : failures.push({ name: v.name, expected: 'refused', actual: r.kind === 'ok' ? `accepted, returned ${JSON.stringify(r.value)}` : `${r.kind} — ${r.why}` });
      console.log(`  ${ok ? 'PASS' : 'FAIL'}  refuses: ${v.name}`);
    }
  }
}

// Strain and line records (SPEC 11.9, draft). Their fingerprints are computed exactly as any record's,
// so every implementation answers them with `recordFingerprint`: agreement there shows the
// profile changed no rule. The profile's own form is checked with `strainFingerprint`, which
// refuses fields not in the profile's form and otherwise answers as `recordFingerprint`. An
// implementation that doesn't offer the profile check is asked once with a valid record; if it
// can't answer, its refusals are never counted as passes (an unknown op looks like a refusal
// from out here). It fails them, or with --without-strain-profile they are left out and the
// result says so.
console.log('\nStrain and line records');
const withoutStrain = process.argv.includes('--without-strain-profile');
for (const v of vectors.strainRecords ?? []) {
  const c = await ask('canonicalise', v.fields);
  const r = await ask('recordFingerprint', v.fields);
  const expected = [v.canonical, v.algorithm, v.contentHash, v.fingerprint];
  const ok = c.kind === 'ok' && c.value === v.canonical && r.kind === 'ok' && r.value !== null && typeof r.value === 'object' &&
    same([c.value, r.value.algorithm, r.value.contentHash, r.value.fingerprint], expected);
  ok ? pass++ : failures.push({ name: v.name, expected: JSON.stringify(expected), actual: `canonical: ${outcome(c)}; fingerprint: ${outcome(r)}` });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${v.name}`);
}
const strainRefusalList = vectors.strainRefusals ?? [];
if (strainRefusalList.length) {
  const strainProbe = vectors.strainRecords?.[0];
  const sp = strainProbe ? await ask('strainFingerprint', strainProbe.fields) : { kind: 'broken', why: 'no strain record to ask with' };
  const strainOffers = sp.kind === 'ok' && sp.value !== null && typeof sp.value === 'object' && sp.value.fingerprint === strainProbe.fingerprint;
  if (!strainOffers && withoutStrain) {
    console.log(`  NOT RUN  ${strainRefusalList.length} strain-profile refusals: this implementation does not check the profile (--without-strain-profile)`);
  } else if (!strainOffers) {
    for (const v of strainRefusalList) failures.push({ name: `refuses: ${v.name}`, expected: 'refused by strainFingerprint', actual: `the op is not answered for a valid record (${outcome(sp)})` });
    console.log(`  FAIL  ${strainRefusalList.length} strain-profile refusals: op strainFingerprint is not answered for a valid record (${outcome(sp)}). Use --without-strain-profile to leave them out and say so.`);
  } else {
    for (const v of strainRefusalList) {
      const r = await ask('strainFingerprint', v.fields);
      const ok = r.kind === 'refused';
      ok ? pass++ : failures.push({ name: v.name, expected: 'refused', actual: r.kind === 'ok' ? `accepted, returned ${JSON.stringify(r.value)}` : `${r.kind} — ${r.why}` });
      console.log(`  ${ok ? 'PASS' : 'FAIL'}  refuses: ${v.name}`);
    }
  }
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
