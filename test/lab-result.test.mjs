// Laboratory results v2 (SPEC 11.12): both entry points agree with the published vectors, the
// call forms are valid field schemas, and a statement's own check refuses what a binding needs.
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import * as node from '../dist/index.js';
import * as browser from '../dist/index.browser.js';

const v = JSON.parse(readFileSync(new URL('../conformance/lab-result-v2.json', import.meta.url), 'utf8'));

test('the node and browser entry points give the vectors’ file entries and seals', async () => {
  for (const impl of [node, browser]) {
    for (const s of v.labStatements) assert.deepEqual(await impl.labStatementFile(s.statement), { name: 'lab-result.json', sha256: s.sha256, size: s.size });
    for (const m of v.markSeals) assert.equal(await impl.dnaMarkSeal(m.sequence, m.salt), m.seal);
  }
});

test('every call form is a field schema the claims contract can name, and the kinds map to them', async () => {
  for (const id of Object.values(node.LAB_CALL_SCHEMAS)) {
    const doc = v.schemas[id];
    assert.ok(doc, id);
    assert.equal((await node.fieldSchemaId(doc)).length, 32);
    const file = JSON.parse(readFileSync(new URL(`../profiles/fields/${id.split('/')[2]}-v1.json`, import.meta.url), 'utf8'));
    assert.deepEqual(file, doc);
  }
});

test('a binding is refused with a reason a person can read', async () => {
  const b = v.labBindings.find((x) => !x.bound && x.name === 'the call in the field set disagrees');
  const p = await node.labBindingProblems({ fields: b.fields, statement: b.statement, values: b.values, schemas: v.schemas });
  assert.deepEqual(p, ['the field set’s values do not agree with the statement']);
  assert.deepEqual(node.labStatementProblems(v.labStatements[0].statement), []);
  assert.ok(node.labStatementProblems({ ...v.labStatements[0].statement, subject: 'x' }).some((s) => s.includes('subject')));
});

test('both entry points give the vectors’ name bindings, and refuse the vectors’ refusals', async () => {
  for (const impl of [node, browser]) {
    for (const b of v.labNameBindings) assert.equal(await impl.labNameBinding(b.key, b.subject, b.salt), b.nameBinding, b.name);
    for (const b of v.labNameBindingRefusals) await assert.rejects(impl.labNameBinding(b.key, b.subject, b.salt), b.name);
  }
  const salted = v.labStatements.find((s) => s.statement.bindingSalt);
  assert.ok(salted, 'a statement with a binding salt');
  assert.deepEqual(node.labStatementProblems(salted.statement), []);
  assert.ok(node.labStatementProblems({ ...salted.statement, bindingSalt: '11'.repeat(32) }).some((s) => s.includes('bindingSalt')));
});

test('an outsider with a lab’s key and a list of proof codes can no longer tell which record it tested', async () => {
  const { createHash, randomBytes } = await import('node:crypto');
  const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest('hex');
  const key = randomBytes(64).toString('hex');
  // The proof codes an outsider might hold: every record it has seen a check link for.
  const codes = Array.from({ length: 200 }, () => randomBytes(32).toString('hex'));
  const tested = codes[137];
  // The attack on the earlier, unsalted binding: hash each code with the key and compare.
  const UNSALTED = Buffer.from('veilcore:lab-result-binding:v2\0');
  const unsalted = (c) => sha(UNSALTED, Buffer.from(key, 'hex'), Buffer.from(c, 'hex'));
  assert.equal(codes.filter((c) => unsalted(c) === unsalted(tested)).length, 1, 'the unsalted binding gave the record away');
  // The binding the lab publishes now. The outsider has the key and the codes, and even the salt
  // of another result of the same lab, disclosed to it on that result's check link.
  const salt = randomBytes(32).toString('hex');
  const published = await node.labNameBinding(key, tested, salt);
  const otherSalt = randomBytes(32).toString('hex');
  for (const c of codes) {
    assert.notEqual(unsalted(c), published);
    assert.notEqual(await node.labNameBinding(key, c, otherSalt), published);
  }
  // The checker the holder shows the result to has the salt in the statement, and confirms it.
  assert.equal(await node.labNameBinding(key, tested, salt), published);
  assert.notEqual(await node.labNameBinding(key, codes[0], salt), published);
});

test('a viability result: its call and stage are the field set, its pairs read as the vectors say', async () => {
  for (const impl of [node, browser]) {
    assert.equal(impl.LAB_CALL_SCHEMAS.viability, 'veilcore/schema/viability/v1');
    for (const p of v.labViabilityPairs)
      assert.equal(impl.labViabilityPairProblems(p).length === 0, p.paired, p.name);
  }
  const after = v.labStatements.find((s) => s.statement.kind === 'viability' && s.statement.result.stage === 'after');
  const before = v.labStatements.find((s) => s.statement.kind === 'viability' && s.statement.result.stage === 'before');
  assert.deepEqual(node.labCallValues(after.statement).slice(0, 3), ['0', '1', null]);
  assert.deepEqual(node.labCallValues(before.statement).slice(0, 3), ['1', '0', null]);
  // The strain is named by proof code only: nothing of the strain record is in the statement.
  assert.match(after.statement.result.strain, /^[0-9a-f]{64}$/);
  // An invalid run is never signed: a positive control that did not grow is refused, by name.
  const bad = { ...after.statement, result: { ...after.statement.result, controls: { positive: 'x', positiveGrew: false } } };
  assert.ok(node.labStatementProblems(bad).some((s) => s.includes('positive control')));
  // A before-sample can't name a before-sample, and an after-sample must say its kill step.
  const noKill = { ...after.statement, result: { ...after.statement.result, killStep: undefined } };
  assert.ok(node.labStatementProblems(JSON.parse(JSON.stringify(noKill))).some((s) => s.includes('killStep')));
});
