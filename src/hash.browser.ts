// SHA-256 in a browser. WebCrypto only, no Node import to externalise.
// SPDX-License-Identifier: Apache-2.0

export const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export const sha256Hex = async (text: string): Promise<string> =>
  toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))));

export const newNonce = (): string => {
  const a = new Uint8Array(32);
  crypto.getRandomValues(a);
  return toHex(a);
};
