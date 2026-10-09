// A report paired with a ledger identity (SPEC 3.7).
//
// A ledger pairing of a report's raw SHA-256 can be copied: the value is public once sent,
// even before it lands, and anyone can pair it under their own identity first. So the
// value paired is a binding instead:
//
//   binding = H("veilcore:v1:dnapair", reportHash, identity, salt)
//
// H as in SPEC 4.5 (SHA-256 over 32-byte elements, the tag right-padded with zero bytes).
// It hides the report, holds only for the identity inside it, and cannot be made for
// another identity without the report's hash. The holder keeps the salt with the report.
//
// SPDX-License-Identifier: Apache-2.0

import { hashElements } from './fields.js';
import { toHex } from './hash.js';

/** The binding's tag (SPEC 3.7). */
export const DNA_PAIR_TAG = 'veilcore:v1:dnapair';

const HEX64 = /^[0-9a-f]{64}$/;

const bytes32 = (h: unknown, what: string): Uint8Array => {
  if (typeof h !== 'string' || !HEX64.test(h)) throw new Error(`${what} must be 64 lowercase hex characters`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
};

const tagBytes = (t: string): Uint8Array => {
  const b = new Uint8Array(32);
  b.set(new TextEncoder().encode(t));
  return b;
};

/**
 * The value a ledger pairing publishes for a report (SPEC 3.7), as 64 lowercase hex
 * characters. `reportHash` is the SHA-256 of the report file, `identity` the ledger
 * identity of the record pairing it (section 3.6), `salt` 32 random bytes the holder
 * keeps; each as 64 lowercase hex characters, or it is refused.
 */
export const dnaPairBinding = async (reportHash: string, identity: string, salt: string): Promise<string> =>
  toHex(
    await hashElements(
      tagBytes(DNA_PAIR_TAG),
      bytes32(reportHash, 'reportHash'),
      bytes32(identity, 'identity'),
      bytes32(salt, 'salt'),
    ),
  );
