// The two entry points must export the same surface.
//
// They diverged silently once: batch.js was added to the Node entry and not the
// browser one, so a frontend installing this package got a build error on an export
// that exists in the docs. A test is cheaper than remembering.
import { test } from 'node:test';
import assert from 'node:assert';
import * as node from '../dist/index.js';
import * as browser from '../dist/index.browser.js';

test('both entry points export the same names', () => {
  const a = Object.keys(node).sort();
  const b = Object.keys(browser).sort();
  assert.deepEqual(b, a, `browser is missing: ${a.filter((k) => !b.includes(k)).join(', ') || 'nothing'}`);
});

// The package is ESM. require() reaches the same module through the exports map's
// "default" condition on Node versions with require(esm) (20.19+, 22.12+); before the
// map had "default", require() failed with ERR_PACKAGE_PATH_NOT_EXPORTED everywhere.
import { createRequire } from 'node:module';
test('require() and the package.json subpath resolve through the exports map', () => {
  const require = createRequire(import.meta.url);
  assert.equal(require('veilcore-records/package.json').name, 'veilcore-records');
  const [maj, min] = process.versions.node.split('.').map(Number);
  const requireEsm = (maj === 20 && min >= 19) || (maj === 22 && min >= 12) || maj >= 23;
  if (!requireEsm) return;
  const cjs = require('veilcore-records');
  assert.deepEqual(Object.keys(cjs).sort(), Object.keys(node).sort());
});
