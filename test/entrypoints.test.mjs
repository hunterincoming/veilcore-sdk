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
