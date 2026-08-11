// SHA-256, using whatever the runtime provides.
//
// WebCrypto in a browser, node:crypto on a server. No dependencies, so a registrar can
// adopt the format without inheriting our toolchain.
// SPDX-License-Identifier: Apache-2.0

export const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export const sha256Hex = async (text: string): Promise<string> => {
  const bytes = new TextEncoder().encode(text);
  const g = globalThis as { crypto?: { subtle?: SubtleCrypto } };
  if (g.crypto?.subtle) {
    return toHex(new Uint8Array(await g.crypto.subtle.digest('SHA-256', bytes)));
  }
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(bytes).digest('hex');
};

/** A 32-byte random nonce, hex encoded. */
export const newNonce = (): string => {
  const a = new Uint8Array(32);
  (globalThis as { crypto: Crypto }).crypto.getRandomValues(a);
  return toHex(a);
};
