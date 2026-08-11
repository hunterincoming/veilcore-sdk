// Canonical serialisation.
//
// A commitment is worthless if two implementations hash the same record differently.
// These rules are the contract between every implementation of the format.
//
// Object keys sorted by code point. Absent optionals omitted, never serialised as null
// — an omitted field and a null field must not produce different hashes for the same
// record. UTF-8, NFC normalised. No insignificant whitespace. Array order preserved,
// because parent order is meaningful in some domains and sorting it would lose that.
//
// SPDX-License-Identifier: Apache-2.0

export const canonicalise = (value: unknown): string => {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'string') return JSON.stringify(value.normalize('NFC'));
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite numbers cannot be canonicalised');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalise).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalise(obj[k])}`).join(',')}}`;
  }
  throw new Error(`cannot canonicalise ${typeof value}`);
};
