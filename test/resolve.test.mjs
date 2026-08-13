// Qualified identifiers.
//
// The property being protected: a verifier can find the registry that issued a record
// without consulting anything we operate. If the identifier itself does not carry the
// authority, that is impossible and the standard has a hole in it.
import { test } from 'node:test';
import assert from 'node:assert';
import { parseQualifiedId, formatQualifiedId, WELL_KNOWN } from '../dist/index.js';

test('a qualified id carries the issuing authority', () => {
  const p = parseQualifiedId('vc:northfield.example.com/LAB-2026-00417');
  assert.equal(p.authority, 'northfield.example.com');
  assert.equal(p.local, 'LAB-2026-00417');
});

test('the local part is whatever the issuer already uses', () => {
  // Adoption is cheap only if a registrar keeps its own identifiers unchanged.
  for (const local of ['LAB-2026-00417', 'a/b/c', 'VEIL-9D75F6', '2026.417/rev2']) {
    assert.equal(parseQualifiedId(`vc:x.example/${local}`).local, local);
  }
});

test('authorities are case-insensitive, like domain names', () => {
  assert.equal(parseQualifiedId('vc:Northfield.Example.COM/x').authority, 'northfield.example.com');
});

test('a bare local identifier is not qualified', () => {
  // An unqualified id is still valid within its own registry; it just cannot be
  // resolved by a stranger, and the type system should say so.
  assert.equal(parseQualifiedId('LAB-2026-00417'), null);
  assert.equal(parseQualifiedId('vc:no-slash'), null);
  assert.equal(parseQualifiedId(''), null);
});

test('formatting round-trips', () => {
  const id = formatQualifiedId('Northfield.Example.com', 'LAB-417');
  assert.equal(id, 'vc:northfield.example.com/LAB-417');
  const p = parseQualifiedId(id);
  assert.equal(p.authority, 'northfield.example.com');
  assert.equal(p.local, 'LAB-417');
});

test('the well-known path follows RFC 8615', () => {
  assert.match(WELL_KNOWN, /^\/\.well-known\//);
});
