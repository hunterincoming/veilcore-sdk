// Release gate: list exactly what `npm publish` would upload and refuse anything that
// should never ship. Run by prepublishOnly, after a clean build and the tests.
// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from 'node:child_process';

const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { encoding: 'utf8' });
const [{ files, entryCount, size }] = JSON.parse(out);
const paths = files.map((f) => f.path);

// Things that are fine in the repository and wrong in the tarball: compiled Python (not
// built from the tagged source), the TypeScript sources and tests, and above all the
// TEST-ONLY RFC 3161 keys under test/fixtures.
const FORBIDDEN = [/(^|\/)__pycache__\//, /\.pyc$/, /^src\//, /^test\//, /^scripts\//, /\.key$/, /\.pem$/, /(^|\/)node_modules\//, /(^|\/)\.env/];
const bad = paths.filter((p) => FORBIDDEN.some((re) => re.test(p)));
const REQUIRED = ['dist/index.js', 'dist/index.d.ts', 'dist/index.browser.js', 'bin/veilcore.mjs', 'conformance/vectors.json', 'conformance/impl.py', 'SPEC.md', 'package.json'];
const missing = REQUIRED.filter((p) => !paths.includes(p));

if (bad.length || missing.length) {
  if (bad.length) console.error(`check-pack: would publish files that must not ship:\n  ${bad.join('\n  ')}`);
  if (missing.length) console.error(`check-pack: the tarball is missing:\n  ${missing.join('\n  ')}`);
  process.exit(1);
}
console.log(`check-pack: ${entryCount} files, ${size} bytes packed, nothing that should not ship.`);
