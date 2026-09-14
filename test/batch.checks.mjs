/**
 * What a batch proof is and is not.
 *
 * A proof is a file a holder keeps for years and hands to an examiner, so it
 * arrives truncated, edited or half-copied — and the obvious
 * `if (!await verifyInclusion(p))` has to report that rather than throw.
 *
 *   node batch-checks.mjs
 */
import { buildBatch, verifyInclusion } from '../dist/index.js';

let failures = 0;
const ok = (n, c, d) => { if (c) console.log(`OK   ${n}`); else { console.error(`FAIL ${n}${d ? `\n     ${d}` : ''}`); failures++; } };
const refuses = async (p) => { try { return (await verifyInclusion(p)) === false; } catch { return false; } };

const a = 'aa'.repeat(32), b = 'bb'.repeat(32), c = 'cc'.repeat(32), d = 'dd'.repeat(32);
const batch = await buildBatch([a, b, c], 'B1');
const good = batch.proofs[a];

console.log('\n== a genuine proof ==');
ok('verifies', (await verifyInclusion(good)) === true);

console.log('\n== malformed proofs refuse rather than throw ==');
ok('null', await refuses(null), 'reading .path off null took the caller down');
ok('undefined', await refuses(undefined));
ok('no path', await refuses({ commitment: good.commitment, root: good.root }));
ok('path is not an array', await refuses({ ...good, path: 'nope' }));
ok('step is missing its sibling', await refuses({ ...good, path: [{ siblingIsLeft: false }] }));
ok('step direction is not a boolean', await refuses({ ...good, path: [{ sibling: a, siblingIsLeft: 'yes' }] }));
ok('commitment is not a string', await refuses({ ...good, commitment: 42 }));
ok('path longer than the cap', await refuses({ ...good, path: Array(65).fill({ sibling: a, siblingIsLeft: false }) }));

console.log('\n== a proof does not verify against the wrong thing ==');
ok('wrong root', await refuses({ ...good, root: 'ff'.repeat(32) }));
ok('another record\'s commitment', await refuses({ ...good, commitment: d }));
ok('a flipped direction', await refuses({
  ...good,
  path: good.path.map((s) => ({ ...s, siblingIsLeft: !s.siblingIsLeft })),
}), 'siblingIsLeft and "this node is left" are exact inverses; half a proof verifies under either reading');

console.log('\n== the root is a function of the set, not the call ==');
{
  const dup = await buildBatch([a, b, c, c], 'B2');
  ok('a repeated commitment does not change the root', batch.root === dup.root,
     'a caller passing the same commitment twice would otherwise get a different root for the same set');
  const reordered = await buildBatch([c, a, b], 'B3');
  ok('insertion order does not change the root', batch.root === reordered.root,
     'a batch has to be rebuildable by someone who was not there');
  const bigger = await buildBatch([a, b, c, d], 'B4');
  ok('a different set gives a different root', batch.root !== bigger.root);
}

console.log('\n== an interior node is not a leaf ==');
{
  const lifted = { ...good, commitment: good.path[0]?.sibling ?? '' };
  ok('an interior hash cannot be presented as a commitment', await refuses(lifted),
     'this is what the leaf and node domain separators exist to stop');
}

console.log('\n== an empty batch is refused ==');
{
  let threw = false;
  try { await buildBatch([], 'B5'); } catch { threw = true; }
  ok('building an empty batch throws', threw, 'a root over nothing proves nothing and should not be constructible');
}

console.log(`\n${failures === 0 ? 'no findings' : `${failures} finding(s)`}`);
process.exit(failures === 0 ? 0 : 1);
