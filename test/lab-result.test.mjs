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
