// Finding the registry that holds a record.
//
// If anyone can operate a registry, a verifier holding a record identifier has to be
// able to find the one that issued it. The obvious answer is a central directory, and
// the obvious answer is wrong: a study of failed persistent-identifier systems found
// the common cause was reliance on a central authority or infrastructure, and even DOI
// carries that weakness because prefix allocation sits with one organisation.
//
// So resolution uses names issuers already control. A registrar identifies itself by a
// domain it owns, and a verifier finds the registry by asking that domain. There is no
// prefix to allocate, no authority to petition, and nothing that stops working if we do.
// GS1 resolves barcodes the same way.
//
// SPDX-License-Identifier: Apache-2.0

/** The well-known path a registrar publishes, per RFC 8615. */
export const WELL_KNOWN = '/.well-known/veilcore-registry';

export type RegistryDescriptor = {
  /** Human-readable name of the operator. */
  name: string;
  /** Base URL for record lookups. */
  api: string;
  /** Format versions this registry issues. */
  formatVersions: string[];
  /** Where this registry anchors, if it does. */
  anchors?: { chain: string; network: string; contractAddress?: string }[];
  /** Optional public key, so a registrar can sign its own statements. */
  publicKey?: string;
};

/**
 * A qualified record identifier.
 *
 * `vc:northfield.example.com/LAB-2026-00417`
 *
 * The authority is a domain the issuer controls. The local part is whatever they use
 * internally — their own identifiers, unchanged, which is what makes adoption cheap.
 */
export type QualifiedId = { authority: string; local: string };

const ID_PATTERN = /^vc:([a-z0-9.-]+)\/(.+)$/i;

export const parseQualifiedId = (id: string): QualifiedId | null => {
  const m = ID_PATTERN.exec(id.trim());
  return m ? { authority: m[1].toLowerCase(), local: m[2] } : null;
};

export const formatQualifiedId = (authority: string, local: string): string =>
  `vc:${authority.toLowerCase()}/${local}`;

/**
 * Find the registry for an authority.
 *
 * One HTTPS request to a domain the issuer controls. No central directory is consulted,
 * and none exists to be consulted.
 */
export const resolveRegistry = async (authority: string): Promise<RegistryDescriptor | null> => {
  try {
    const res = await fetch(`https://${authority}${WELL_KNOWN}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) return null;
    const d = (await res.json()) as RegistryDescriptor;
    return d && typeof d.api === 'string' ? d : null;
  } catch {
    return null;
  }
};

/**
 * Retrieve a record given only its qualified identifier.
 *
 * Two requests: one to find the registry, one to ask it. Neither touches infrastructure
 * operated by the authors of this format.
 */
export const resolveRecord = async (
  qualifiedId: string,
): Promise<{ registry: RegistryDescriptor; record: unknown } | { error: string }> => {
  const parsed = parseQualifiedId(qualifiedId);
  if (!parsed) return { error: 'not a qualified record identifier' };

  const registry = await resolveRegistry(parsed.authority);
  if (!registry) return { error: `no registry published at ${parsed.authority}` };

  try {
    const res = await fetch(`${registry.api.replace(/\/$/, '')}/records/${encodeURIComponent(parsed.local)}`);
    if (!res.ok) return { error: `registry at ${parsed.authority} has no record ${parsed.local}` };
    return { registry, record: await res.json() };
  } catch {
    return { error: `registry at ${parsed.authority} could not be reached` };
  }
};
