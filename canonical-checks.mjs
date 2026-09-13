/**
 * Canonicalisation edge cases.
 *
 * Two implementations that serialise the same record differently produce
 * different commitments, and one of them then reports a genuine record as
 * altered. Every case here is something a caller could plausibly pass where the
 * right answer is "refuse", because silently accepting it is how two
 * implementations diverge without either one failing.
 *
 *   node canonical-checks.mjs      (from the veilcore-sdk root)
 */
import { canonicalise } from './dist/index.js';

let failures = 0;
const ok = (name, cond, detail) => {
  if (cond) console.log(`OK   ${name}`);
  else { console.error(`FAIL ${name}${detail ? `\n     ${detail}` : ''}`); failures++; }
};
const note = (s) => console.log(`     ${s}`);
const out = (v) => { try { return canonicalise(v); } catch (e) { return `THREW: ${e.message}`; } };

// ── things that are objects to typeof but are not records ───────────────────
console.log('\n== non-plain objects ==');
{
  const cases = [
    ['Date', new Date('2026-01-01')],
    ['Map', new Map([['a', 1]])],
    ['Set', new Set([1, 2])],
    ['Uint8Array', new Uint8Array([1, 2, 3])],
    ['RegExp', /abc/],
    ['class instance', new (class Foo { constructor() { this.a = 1; } })()],
  ];
  for (const [name, value] of cases) {
    const r = out(value);
    note(`${name.padEnd(16)} -> ${r}`);
  }

  const dateOut = out(new Date('2026-01-01'));
  ok('a Date is refused rather than serialised as {}', dateOut.startsWith('THREW'),
     'a Date canonicalises to an empty object, so the commitment covers none of it and\n' +
     '     another implementation given the same logical record disagrees');

  const mapOut = out(new Map([['a', 1]]));
  ok('a Map is refused rather than serialised as {}', mapOut.startsWith('THREW'));

  const taOut = out(new Uint8Array([1, 2, 3]));
  ok('a typed array is refused or serialised unambiguously',
     taOut.startsWith('THREW') || taOut === '{"0":1,"1":2,"2":3}',
     'a typed array that silently becomes an object of index keys is a shape another\n' +
     '     implementation will not reproduce');

  const clsOut = out(new (class Foo { constructor() { this.a = 1; } })());
  ok('a class instance serialises as its own enumerable fields', clsOut === '{"a":1}',
     'own enumerable properties are what JSON.stringify would take, so this is the\n' +
     '     one case where matching JSON is right');
}

// ── the rules the spec states ───────────────────────────────────────────────
console.log('\n== stated rules ==');
{
  ok('null is refused at the top level', out(null).startsWith('THREW'));
  ok('null inside an object is refused', out({ a: null }).startsWith('THREW'));
  ok('null inside an array is refused', out({ a: [1, null] }).startsWith('THREW'));
  ok('undefined is refused at the top level', out(undefined).startsWith('THREW'));
  ok('absent optionals are omitted, not refused', out({ a: 1, b: undefined }) === '{"a":1}');
  ok('non-finite numbers are refused', out({ a: Infinity }).startsWith('THREW'));
  ok('NaN is refused', out({ a: NaN }).startsWith('THREW'));

  // Written as escapes, not literals: the two forms are identical once a source
  // file is normalised, so an earlier version of this test built a one-key object
  // and proved nothing.
  const collideObj = {};
  collideObj['\u00e9'] = 1;              // NFC
  collideObj['\u0065\u0301'] = 2;        // NFD
  const collide = out(collideObj);
  note(`normalisation collision -> ${collide}`);
  ok('keys colliding after NFC are refused', collide.startsWith('THREW'));
}

// ── ordering, the bug an external reviewer found ────────────────────────────
console.log('\n== key ordering ==');
{
  const r = out({ '\u{1F600}': 2, '\uFF61': 1 });   // U+1F600 above the BMP, U+FF61 below
  note(`{emoji, halfwidth stop} -> ${r}`);
  ok('sorted by code point, not UTF-16 code unit', r.indexOf('\uFF61') < r.indexOf('\u{1F600}'),
     'JavaScript default sort puts the astral character first because its surrogate leads\n' +
     '     with 0xD800; every other language disagrees');
}

// ── numbers ─────────────────────────────────────────────────────────────────
console.log('\n== numbers ==');
{
  note(`1e-7        -> ${out({ a: 1e-7 })}`);
  note(`-0          -> ${out({ a: -0 })}`);
  note(`1e21        -> ${out({ a: 1e21 })}`);
  ok('negative zero serialises as zero', out({ a: -0 }) === '{"a":0}',
     'RFC 8785 requires it; two implementations disagreeing here differ on a value that\n' +
     '     compares equal in every language');
}

console.log(`\n${failures === 0 ? 'no findings' : `${failures} finding(s) above`}`);
process.exit(0);
