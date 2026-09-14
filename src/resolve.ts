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
 *
 * ⚠️ WHAT THIS DOES NOT DO, and section 11.5.1 says a verifier should: it does not pin
 * the registry's key across lookups, and it does not check whether the domain still
 * belongs to whoever it belonged to when the record was received. Whoever holds the
 * domain today answers for it. A lapsed domain acquired by someone else resolves as
 * the registry for every record naming that authority, and this function cannot tell.
 *
 * The defence is elsewhere and the spec states it: resolution is not evidence, and the
 * anchor governs. A verifier relying on a record should be comparing the registry's
 * public key against the one they recorded when they received it, which is a decision
 * only the verifier can make because only they know what they saw before.
 */
export const resolveRegistry = async (authority: string): Promise<RegistryDescriptor | null> => {
  try {
    const res = await fetch(`https://${authority}${WELL_KNOWN}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) return null;
    const d: unknown = await res.json();
    if (typeof d !== 'object' || d === null) return null;
    const desc = d as RegistryDescriptor;
    if (typeof desc.api !== 'string') return null;

    // The api URL must belong to the authority that published it. Without this, the
    // whole argument for resolving through a name the issuer controls stops at the
    // first hop: the descriptor could name any host, and a verifier following it
    // would fetch from somewhere the issuer does not control on the strength of a
    // domain they do. For a verifier running server-side that is a request-forgery
    // primitive inside a function called "resolve a record".
    let api: URL;
    try {
      api = new URL(desc.api);
    } catch {
      return null;
    }
    if (api.protocol !== 'https:') return null;
    const host = api.hostname.toLowerCase();
    const auth = authority.toLowerCase();
    if (host !== auth && !host.endsWith(`.${auth}`)) return null;

    return desc;
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
