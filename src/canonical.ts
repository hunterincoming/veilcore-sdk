// Canonical serialisation, per specification section 4.4.
//
// Follows RFC 8785 (JSON Canonicalization Scheme) where they overlap. Two implementations
// that serialise the same record differently produce different commitments, and one of
// them then reports a genuine record as altered. Every rule here exists because that
// happened, or because it would have.
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Sort by Unicode code point, not by UTF-16 code unit.
 *
 * JavaScript's default comparison — and `Array.prototype.sort` with no comparator — orders
 * by code unit, which puts characters above U+FFFF before characters in U+E000–U+FFFF
 * because the surrogate pair leads with 0xD800-something. Python and most other languages
 * compare by code point and disagree.
 *
 * Found by an external reviewer on `{"｡":1,"😀":2}`, where the two orders differ.
 */
const byCodePoint = (a: string, b: string): number => {
  const ai = Array.from(a);
  const bi = Array.from(b);
  const n = Math.min(ai.length, bi.length);
  for (let i = 0; i < n; i++) {
    const x = ai[i].codePointAt(0) as number;
    const y = bi[i].codePointAt(0) as number;
    if (x !== y) return x - y;
  }
  return ai.length - bi.length;
};

/** NFC, applied to keys as well as values, and before sorting. */
const nfc = (s: string): string => s.normalize('NFC');

/**
 * Serialise a number per RFC 8785 section 3.2.2.3.
 *
 * ECMAScript's shortest round-trip form, which `String(n)` already produces, except that
 * ECMAScript writes exponents as `1e-7` while some languages pad to `1e-07`. This is the
 * canonical form; other implementations normalise to it.
 */
const num = (n: number): string => {
  if (!Number.isFinite(n)) throw new Error('non-finite numbers cannot be committed');
  if (Number.isInteger(n) && Math.abs(n) < 1e21) return String(n);
  return String(n);
};

/** Escape per RFC 8785 section 3.2.2.2: shortest form, lowercase hex. */
const str = (s: string): string => {
  let out = '"';
  for (const ch of nfc(s)) {
    const c = ch.codePointAt(0) as number;
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c < 0x20) out += `\\u${c.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return out + '"';
};

/**
 * Canonicalise a value for commitment.
 *
 * Throws on null and on a post-normalisation key collision. Both are rejections rather
 * than resolutions: an implementation that resolves them has to choose how, and two
 * implementations choose differently.
 */
export const canonicalise = (value: unknown): string => {
  if (value === null) {
    throw new Error('null cannot be committed: omit the field instead (spec 4.4 rule 4)');
  }
  if (value === undefined) {
    throw new Error('undefined cannot be committed: omit the field instead');
  }
  if (typeof value === 'boolean') return String(value);
  if (typeof value === 'number') return num(value);
  if (typeof value === 'string') return str(value);
  if (Array.isArray(value)) return `[${value.map(canonicalise).join(',')}]`;

  if (typeof value === 'object') {
    const src = value as Record<string, unknown>;
    // Omit absent optionals. A present null is rejected above, not silently dropped.
    const present = Object.keys(src).filter((k) => src[k] !== undefined);

    // Normalise keys, then check for collisions, then sort. Order matters: two keys that
    // differ only by normalisation form are the same key afterwards.
    const seen = new Map<string, string>();
    for (const k of present) {
      const n = nfc(k);
      const prior = seen.get(n);
      if (prior !== undefined && prior !== k) {
        throw new Error(
          `keys "${prior}" and "${k}" are identical after Unicode normalisation; ` +
          'the record is invalid (spec 4.4 rule 1)',
        );
      }
      seen.set(n, k);
    }

    const parts = [...seen.keys()]
      .sort(byCodePoint)
      .map((n) => `${str(n)}:${canonicalise(src[seen.get(n) as string])}`);
    return `{${parts.join(',')}}`;
  }

  throw new Error(`cannot canonicalise ${typeof value}`);
};
