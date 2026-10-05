// Reading registry answers. Internal: not exported from the package entry points.
// SPDX-License-Identifier: Apache-2.0

/** Largest registry answer read, in bytes. A descriptor, record or verdict is a few kilobytes. */
export const MAX_REGISTRY_RESPONSE_BYTES = 1 << 20;

/**
 * Read a JSON answer with a size cap, refusing redirects (the caller sets that on the
 * request). Undefined when the body is too large or is not JSON.
 */
export const readJsonBounded = async (res: Response, max = MAX_REGISTRY_RESPONSE_BYTES): Promise<unknown> => {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > max) return undefined;
  if (!res.body) return undefined;
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel().catch(() => undefined);
      return undefined;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    all.set(c, o);
    o += c.length;
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(all));
  } catch {
    return undefined;
  }
};

