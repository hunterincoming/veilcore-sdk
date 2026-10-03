// RFC 3161 timestamp tokens: parsed and checked with WebCrypto, no dependencies.
//
// What a token proves, when its checks pass: a key whose certificate is marked for
// time-stamping signed a statement that the stamped bytes' hash existed at `genTime`.
// What it does NOT prove on its own: that the key belongs to a TSA anyone should trust.
// That needs the certificate chain to a trusted root, the provider's status on a trusted
// list, and revocation, none of which this module checks. It says so in every result.
//
// The parser is deliberately narrow. It reads DER (not BER), single-byte tags, definite
// lengths of at most four bytes, and only the structures RFC 3161 and RFC 5652 put in a
// timestamp token. Anything else is refused. Every length is checked against what
// remains; every loop advances by at least two bytes; the input is capped in size.
// Malformed input returns ok:false and never throws.
//
// SPDX-License-Identifier: Apache-2.0

/** One thing that was checked, and whether it held. */
export type TimestampCheck = { ok: boolean; what: string };

export type TimestampVerification = {
  /** True only when every check passed. Even then, see `notChecked`. */
  ok: boolean;
  /** The time the TSA states, RFC 3339 (UTC). Present whenever the token parsed. */
  genTime?: string;
  /** The signer certificate's subject, for display only (e.g. "C=US, O=..., CN=..."). */
  signerSubject?: string;
  /** The imprint's hash algorithm, e.g. "SHA-256". */
  hashAlgorithm?: string;
  /** TSTInfo serial number, hex. */
  serialNumber?: string;
  /** The TSA policy OID. */
  policy?: string;
  /** The request nonce, hex, if the token carries one. */
  nonce?: string;
  checks: TimestampCheck[];
  /** What a token check of this kind never covers. Always the same three items. */
  notChecked: string[];
};

export type TimestampOptions = {
  /** Further certificates (DER) to find the signer among, when the token does not carry it. */
  certificates?: Uint8Array[];
};

export const TIMESTAMP_NOT_CHECKED: readonly string[] = Object.freeze([
  'certificate chain to a trusted root',
  'qualified status on an EU trusted list',
  'revocation',
]);

/** Largest token accepted, in bytes. Real tokens with a full chain are a few kilobytes. */
export const MAX_TOKEN_BYTES = 1 << 20;
const MAX_CHILDREN = 4096;
const MAX_OID_ARCS = 32;

// ─────────────────────────────────────────────────────────────── DER

class DerError extends Error {}

type Node = { buf: Uint8Array; tag: number; start: number; hdr: number; len: number; end: number };

const read = (buf: Uint8Array, pos: number, limit: number): Node => {
  if (pos + 2 > limit) throw new DerError('data ends inside a header');
  const tag = buf[pos];
  if ((tag & 0x1f) === 0x1f) throw new DerError('multi-byte tags are not used in a timestamp token');
  let p = pos + 1;
  const first = buf[p++];
  let len: number;
  if (first < 0x80) {
    len = first;
  } else if (first === 0x80) {
    throw new DerError('indefinite length is not DER');
  } else {
    const n = first & 0x7f;
    if (n > 4) throw new DerError('length field too large');
    if (p + n > limit) throw new DerError('data ends inside a length');
    if (buf[p] === 0) throw new DerError('length not minimally encoded');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
    if (len < 0x80) throw new DerError('length not minimally encoded');
  }
  if (len > limit - p) throw new DerError('length runs past the end of its container');
  return { buf, tag, start: pos, hdr: p - pos, len, end: p + len };
};

const val = (n: Node): Uint8Array => n.buf.subarray(n.start + n.hdr, n.end);
const whole = (n: Node): Uint8Array => n.buf.subarray(n.start, n.end);

const kids = (n: Node, what: string): Node[] => {
  if (!(n.tag & 0x20)) throw new DerError(`${what} is not a constructed value`);
  const out: Node[] = [];
  let p = n.start + n.hdr;
  while (p < n.end) {
    if (out.length >= MAX_CHILDREN) throw new DerError(`${what} has too many elements`);
    const c = read(n.buf, p, n.end);
    out.push(c);
    p = c.end; // c.end >= p + 2, so this always advances
  }
  return out;
};

const expect = (n: Node | undefined, tag: number, what: string): Node => {
  if (!n) throw new DerError(`${what} is missing`);
  if (n.tag !== tag) throw new DerError(`${what} has the wrong type (tag 0x${n.tag.toString(16)})`);
  return n;
};

const T = { BOOL: 0x01, INT: 0x02, BITS: 0x03, OCTETS: 0x04, NULL: 0x05, OID: 0x06, SEQ: 0x30, SET: 0x31, GENTIME: 0x18, UTCTIME: 0x17 };

const oid = (n: Node, what: string): string => {
  expect(n, T.OID, what);
  const v = val(n);
  if (!v.length || v[v.length - 1] & 0x80) throw new DerError(`${what} is not a valid OID`);
  const arcs: number[] = [];
  let acc = 0;
  let started = false;
  for (const b of v) {
    if (!started && b === 0x80) throw new DerError(`${what} is not minimally encoded`);
    started = true;
    acc = acc * 128 + (b & 0x7f);
    if (acc > Number.MAX_SAFE_INTEGER) throw new DerError(`${what} has an arc too large`);
    if (!(b & 0x80)) {
      arcs.push(acc);
      acc = 0;
      started = false;
      if (arcs.length > MAX_OID_ARCS) throw new DerError(`${what} has too many arcs`);
    }
  }
  const head = arcs[0] < 40 ? [0, arcs[0]] : arcs[0] < 80 ? [1, arcs[0] - 40] : [2, arcs[0] - 80];
  return [...head, ...arcs.slice(1)].join('.');
};

const intBytes = (n: Node, what: string): Uint8Array => {
  expect(n, T.INT, what);
  const v = val(n);
  if (!v.length) throw new DerError(`${what} is empty`);
  return v;
};
const smallInt = (n: Node, what: string): number => {
  const v = intBytes(n, what);
  if (v.length > 4 || v[0] & 0x80) throw new DerError(`${what} is out of range`);
  return v.reduce((a, b) => a * 256 + b, 0);
};

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const eq = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

const genTime = (n: Node): string => {
  expect(n, T.GENTIME, 'genTime');
  const s = String.fromCharCode(...val(n));
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z$/.exec(s);
  if (!m) throw new DerError('genTime is not a UTC GeneralizedTime');
  return checkedIso(m[1], m[2], m[3], m[4], m[5], m[6], m[7]);
};

const certTime = (n: Node): string => {
  const s = String.fromCharCode(...val(n));
  if (n.tag === T.UTCTIME) {
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new DerError('certificate UTCTime is malformed');
    return checkedIso(String(Number(m[1]) < 50 ? 2000 + Number(m[1]) : 1900 + Number(m[1])), m[2], m[3], m[4], m[5], m[6]);
  }
  if (n.tag === T.GENTIME) {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new DerError('certificate GeneralizedTime is malformed');
    return checkedIso(m[1], m[2], m[3], m[4], m[5], m[6]);
  }
  throw new DerError('certificate validity is not a time');
};

const checkedIso = (y: string, mo: string, d: string, h: string, mi: string, s: string, frac?: string): string => {
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${s}${frac ? '.' + frac : ''}Z`;
  const t = new Date(`${y}-${mo}-${d}T${h}:${mi}:${s}Z`);
  if (Number.isNaN(t.getTime()) || t.toISOString().slice(0, 19) !== `${y}-${mo}-${d}T${h}:${mi}:${s}`) {
    throw new DerError('time is not a real calendar time');
  }
  return iso;
};

// ─────────────────────────────────────────────────────────────── names, for display

const ATTR_NAMES: Record<string, string> = {
  '2.5.4.3': 'CN', '2.5.4.5': 'serialNumber', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
  '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.97': 'organizationIdentifier', '1.2.840.113549.1.9.1': 'emailAddress',
};

const displayString = (n: Node): string => {
  const v = val(n);
  let s: string;
  if (n.tag === 0x1e) {
    // BMPString, UTF-16BE
    s = '';
    for (let i = 0; i + 1 < v.length; i += 2) s += String.fromCharCode((v[i] << 8) | v[i + 1]);
  } else if (n.tag === 0x14) {
    s = String.fromCharCode(...v); // T61String, read as Latin-1
  } else {
    s = new TextDecoder('utf-8', { fatal: false }).decode(v);
  }
  // Display only: nothing from a certificate gets to drive a terminal.
  return s.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
};

const nameString = (n: Node): string => {
  const parts: string[] = [];
  for (const rdn of kids(expect(n, T.SEQ, 'name'), 'name')) {
    for (const atv of kids(expect(rdn, T.SET, 'name component'), 'name component')) {
      const [type, value] = kids(expect(atv, T.SEQ, 'name attribute'), 'name attribute');
      if (!value) throw new DerError('name attribute has no value');
      const id = oid(type, 'name attribute type');
      parts.push(`${ATTR_NAMES[id] ?? id}=${displayString(value)}`);
    }
  }
  return parts.join(', ');
};

// ─────────────────────────────────────────────────────────────── algorithms

const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  eku: '2.5.29.37',
  ski: '2.5.29.14',
  timeStamping: '1.3.6.1.5.5.7.3.8',
  rsa: '1.2.840.113549.1.1.1',
  ec: '1.2.840.10045.2.1',
  p256: '1.2.840.10045.3.1.7',
  p384: '1.3.132.0.34',
};

const HASHES: Record<string, string> = {
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
};
const RSA_SIGS: Record<string, string> = {
  '1.2.840.113549.1.1.11': 'SHA-256',
  '1.2.840.113549.1.1.12': 'SHA-384',
  '1.2.840.113549.1.1.13': 'SHA-512',
};
const ECDSA_SIGS: Record<string, string> = {
  '1.2.840.10045.4.3.2': 'SHA-256',
  '1.2.840.10045.4.3.3': 'SHA-384',
  '1.2.840.10045.4.3.4': 'SHA-512',
};
const CURVES: Record<string, { name: string; size: number }> = {
  [OID.p256]: { name: 'P-256', size: 32 },
  [OID.p384]: { name: 'P-384', size: 48 },
};

const algId = (n: Node, what: string): { id: string; params?: Node } => {
  const [id, params, extra] = kids(expect(n, T.SEQ, what), what);
  if (extra) throw new DerError(`${what} has unexpected fields`);
  return { id: oid(id, what), params };
};

/** A hash AlgorithmIdentifier: SHA-256/384/512 only, parameters absent or NULL. */
const hashAlg = (n: Node, what: string): string => {
  const { id, params } = algId(n, what);
  const name = HASHES[id];
  if (!name) throw new Unsupported(`${what} ${id} is not SHA-256, SHA-384 or SHA-512`);
  if (params && (params.tag !== T.NULL || params.len !== 0)) throw new DerError(`${what} has unexpected parameters`);
  return name;
};

class Unsupported extends Error {}

const subtle = async (): Promise<SubtleCrypto> => {
  const g = globalThis as { crypto?: { subtle?: SubtleCrypto } };
  if (g.crypto?.subtle) return g.crypto.subtle;
  const nodeCrypto = await import(/* @vite-ignore */ 'node' + ':crypto');
  return nodeCrypto.webcrypto.subtle as SubtleCrypto;
};

const digest = async (alg: string, data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await (await subtle()).digest(alg, data as BufferSource));

// ─────────────────────────────────────────────────────────────── base64

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Strict base64 (standard alphabet, padding optional, whitespace ignored). Throws on anything else. */
export const decodeBase64 = (s: string): Uint8Array => {
  const clean = s.replace(/\s+/g, '').replace(/=+$/, '');
  if (clean.length % 4 === 1) throw new Error('not base64');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (const ch of clean) {
    const v = B64.indexOf(ch);
    if (v < 0) throw new Error('not base64');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
};

// ─────────────────────────────────────────────────────────────── structures

type Cert = {
  der: Uint8Array;
  serial: Uint8Array;
  issuer: Uint8Array;
  subject: string;
  notBefore: string;
  notAfter: string;
  spki: Uint8Array;
  keyAlg: string;
  curve?: string;
  ski?: Uint8Array;
  eku?: string[];
};

const parseCert = (n: Node): Cert => {
  const [tbs] = kids(expect(n, T.SEQ, 'certificate'), 'certificate');
  const f = kids(expect(tbs, T.SEQ, 'certificate body'), 'certificate body');
  let i = 0;
  if (f[i]?.tag === 0xa0) i++; // version
  const serial = intBytes(f[i++], 'certificate serial number');
  expect(f[i++], T.SEQ, 'certificate signature algorithm');
  const issuer = expect(f[i++], T.SEQ, 'certificate issuer');
  const validity = kids(expect(f[i++], T.SEQ, 'certificate validity'), 'certificate validity');
  if (validity.length !== 2) throw new DerError('certificate validity is malformed');
  const subject = expect(f[i++], T.SEQ, 'certificate subject');
  const spkiNode = expect(f[i++], T.SEQ, 'certificate public key');
  const [keyAlgNode, keyBits] = kids(spkiNode, 'certificate public key');
  expect(keyBits, T.BITS, 'certificate public key bits');
  const keyAlg = algId(keyAlgNode, 'public key algorithm');
  const cert: Cert = {
    der: whole(n),
    serial,
    issuer: whole(issuer),
    subject: nameString(subject),
    notBefore: certTime(validity[0]),
    notAfter: certTime(validity[1]),
    spki: whole(spkiNode),
    keyAlg: keyAlg.id,
    curve: keyAlg.id === OID.ec && keyAlg.params?.tag === T.OID ? oid(keyAlg.params, 'curve') : undefined,
  };
  for (; i < f.length; i++) {
    if (f[i].tag !== 0xa3) continue;
    const [exts] = kids(f[i], 'certificate extensions');
    for (const ext of kids(expect(exts, T.SEQ, 'certificate extensions'), 'certificate extensions')) {
      const e = kids(expect(ext, T.SEQ, 'extension'), 'extension');
      const id = oid(e[0], 'extension id');
      const value = expect(e[e.length - 1], T.OCTETS, 'extension value');
      const inner = val(value);
      if (id === OID.eku) {
        const seq = read(inner, 0, inner.length);
        if (seq.end !== inner.length) throw new DerError('extended key usage has trailing data');
        cert.eku = kids(expect(seq, T.SEQ, 'extended key usage'), 'extended key usage').map((k) => oid(k, 'key purpose'));
      } else if (id === OID.ski) {
        const os = read(inner, 0, inner.length);
        if (os.end !== inner.length) throw new DerError('subject key identifier has trailing data');
        cert.ski = val(expect(os, T.OCTETS, 'subject key identifier'));
      }
    }
  }
  return cert;
};

type Parsed = {
  tst: {
    der: Uint8Array;
    policy: string;
    hashAlgorithm: string;
    hashedMessage: Uint8Array;
    serialNumber: string;
    genTime: string;
    nonce?: string;
  };
  eContentType: string;
  digestAlgorithm: string;
  signedAttrs: Uint8Array;
  contentTypeAttr?: string;
  messageDigestAttr?: Uint8Array;
  signatureAlgorithm: string;
  signature: Uint8Array;
  sid: { issuer: Uint8Array; serial: Uint8Array } | { ski: Uint8Array };
  certs: Cert[];
};

/** The TimeStampToken (a CMS ContentInfo) inside a token or a full TimeStampResp. */
const tokenNode = (bytes: Uint8Array): Node => {
  const top = read(bytes, 0, bytes.length);
  if (top.end !== bytes.length) throw new DerError('trailing data after the token');
  const k = kids(expect(top, T.SEQ, 'token'), 'token');
  if (k[0]?.tag === T.OID) return top; // already a ContentInfo
  // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }
  const status = kids(expect(k[0], T.SEQ, 'response status'), 'response status');
  const s = smallInt(status[0], 'response status');
  if (s !== 0 && s !== 1) throw new DerError(`the TSA refused the request (status ${s})`);
  if (!k[1]) throw new DerError('the response carries no token');
  return expect(k[1], T.SEQ, 'token');
};

/**
 * The DER TimeStampToken itself, extracted from a full TimeStampResp if that is what was
 * given. This is what `openssl ts -verify -token_in` reads. Undefined if it does not parse.
 */
export const timestampTokenBytes = (token: Uint8Array | string): Uint8Array | undefined => {
  try {
    const bytes = typeof token === 'string' ? decodeBase64(token) : token;
    if (bytes.length > MAX_TOKEN_BYTES) return undefined;
    return new Uint8Array(whole(tokenNode(bytes)));
  } catch {
    return undefined;
  }
};

const parseToken = (bytes: Uint8Array): Parsed => {
  const ci = kids(tokenNode(bytes), 'token');
  if (oid(ci[0], 'content type') !== OID.signedData) throw new DerError('the token is not CMS SignedData');
  const [sd] = kids(expect(ci[1], 0xa0, 'signed data'), 'signed data');
  const f = kids(expect(sd, T.SEQ, 'signed data'), 'signed data');
  let i = 0;
  smallInt(f[i++], 'signed data version');
  expect(f[i++], T.SET, 'digest algorithms');
  const encap = kids(expect(f[i++], T.SEQ, 'encapsulated content'), 'encapsulated content');
  const eContentType = oid(encap[0], 'encapsulated content type');
  const [eContent] = kids(expect(encap[1], 0xa0, 'encapsulated content'), 'encapsulated content');
  const tstDer = val(expect(eContent, T.OCTETS, 'encapsulated content'));

  const certs: Cert[] = [];
  if (f[i]?.tag === 0xa0) {
    for (const c of kids(f[i], 'certificates')) if (c.tag === T.SEQ) certs.push(parseCert(c));
    i++;
  }
  if (f[i]?.tag === 0xa1) i++; // CRLs: not read
  const signers = kids(expect(f[i++], T.SET, 'signer infos'), 'signer infos');
  if (signers.length !== 1) throw new DerError(`a timestamp token has exactly one signer, this has ${signers.length}`);
  if (i !== f.length) throw new DerError('unexpected fields after the signer infos');

  // TSTInfo
  const tstTop = read(tstDer, 0, tstDer.length);
  if (tstTop.end !== tstDer.length) throw new DerError('trailing data after TSTInfo');
  const t = kids(expect(tstTop, T.SEQ, 'TSTInfo'), 'TSTInfo');
  let j = 0;
  if (smallInt(t[j++], 'TSTInfo version') !== 1) throw new DerError('TSTInfo version is not 1');
  const policy = oid(t[j++], 'policy');
  const imprint = kids(expect(t[j++], T.SEQ, 'message imprint'), 'message imprint');
  if (imprint.length !== 2) throw new DerError('message imprint is malformed');
  const hashAlgorithm = hashAlg(imprint[0], 'imprint hash algorithm');
  const hashedMessage = val(expect(imprint[1], T.OCTETS, 'hashed message'));
  const serialNumber = hex(intBytes(t[j++], 'serial number'));
  const gt = genTime(t[j++]);
  if (t[j]?.tag === T.SEQ) j++; // accuracy
  if (t[j]?.tag === T.BOOL) j++; // ordering
  let nonce: string | undefined;
  if (t[j]?.tag === T.INT) nonce = hex(intBytes(t[j++], 'nonce'));
  if (t[j]?.tag === 0xa0) j++; // tsa name
  if (t[j]?.tag === 0xa1) j++; // extensions
  if (j !== t.length) throw new DerError('unexpected fields in TSTInfo');

  // SignerInfo
  const s = kids(expect(signers[0], T.SEQ, 'signer info'), 'signer info');
  let k = 0;
  const siVersion = smallInt(s[k++], 'signer info version');
  const sidNode = s[k++];
  let sid: Parsed['sid'];
  // RFC 5652 5.3: version 1 with issuerAndSerialNumber, version 3 with subjectKeyIdentifier.
  if (sidNode?.tag !== (siVersion === 1 ? T.SEQ : siVersion === 3 ? 0x80 : -1)) {
    throw new DerError(`signer info version ${siVersion} does not match its signer identifier`);
  }
  if (sidNode?.tag === T.SEQ) {
    const [iss, ser] = kids(sidNode, 'signer identifier');
    sid = { issuer: whole(expect(iss, T.SEQ, 'signer issuer')), serial: intBytes(ser, 'signer serial') };
  } else if (sidNode?.tag === 0x80) {
    sid = { ski: val(sidNode) };
  } else {
    throw new DerError('signer identifier is malformed');
  }
  const digestAlgorithm = hashAlg(s[k++], 'signer digest algorithm');
  const attrsNode = expect(s[k++], 0xa0, 'signed attributes');
  let contentTypeAttr: string | undefined;
  let messageDigestAttr: Uint8Array | undefined;
  const seen = new Set<string>();
  for (const a of kids(attrsNode, 'signed attributes')) {
    const [typeNode, values] = kids(expect(a, T.SEQ, 'attribute'), 'attribute');
    const type = oid(typeNode, 'attribute type');
    if (seen.has(type)) throw new DerError(`signed attribute ${type} appears twice`);
    seen.add(type);
    const vs = kids(expect(values, T.SET, 'attribute values'), 'attribute values');
    if (type === OID.contentType || type === OID.messageDigest) {
      if (vs.length !== 1) throw new DerError(`signed attribute ${type} must have exactly one value`);
      if (type === OID.contentType) contentTypeAttr = oid(vs[0], 'content type attribute');
      else messageDigestAttr = val(expect(vs[0], T.OCTETS, 'message digest attribute'));
    }
  }
  const sigAlg = algId(s[k++], 'signature algorithm');
  const signatureAlgorithm = sigAlg.id;
  // RSA identifiers carry NULL (or nothing); ECDSA identifiers carry nothing (RFC 5754).
  const nullOk = signatureAlgorithm === OID.rsa || Boolean(RSA_SIGS[signatureAlgorithm]);
  if (sigAlg.params && !(nullOk && sigAlg.params.tag === T.NULL && sigAlg.params.len === 0)) {
    throw new DerError('signature algorithm has unexpected parameters');
  }
  const signature = val(expect(s[k++], T.OCTETS, 'signature'));
  if (s[k]?.tag === 0xa1) k++; // unsigned attributes
  if (k !== s.length) throw new DerError('unexpected fields in the signer info');

  // signedAttrs are signed as a SET OF, not as the [0] IMPLICIT they are stored under.
  const signedAttrs = new Uint8Array(whole(attrsNode));
  signedAttrs[0] = T.SET;

  return {
    tst: { der: tstDer, policy, hashAlgorithm, hashedMessage, serialNumber, genTime: gt, nonce },
    eContentType,
    digestAlgorithm,
    signedAttrs,
    contentTypeAttr,
    messageDigestAttr,
    signatureAlgorithm,
    signature,
    sid,
    certs,
  };
};

/** ECDSA-Sig-Value (DER) to the fixed-width r||s WebCrypto expects. */
const ecdsaRaw = (sig: Uint8Array, size: number): Uint8Array => {
  const top = read(sig, 0, sig.length);
  if (top.end !== sig.length) throw new DerError('ECDSA signature has trailing data');
  const [r, s, extra] = kids(expect(top, T.SEQ, 'ECDSA signature'), 'ECDSA signature');
  if (extra) throw new DerError('ECDSA signature is malformed');
  const out = new Uint8Array(size * 2);
  [intBytes(r, 'ECDSA r'), intBytes(s, 'ECDSA s')].forEach((v, idx) => {
    let x = v;
    while (x.length > 1 && x[0] === 0) x = x.subarray(1);
    if (x.length > size) throw new DerError('ECDSA signature value too long for the curve');
    out.set(x, idx * size + (size - x.length));
  });
  return out;
};

// ─────────────────────────────────────────────────────────────── verification

/**
 * Verify an RFC 3161 timestamp token against the bytes it is said to stamp.
 *
 * `token` is DER, or base64 of DER: a TimeStampToken, or a full TimeStampResp. `stamped`
 * is the data the TSA client hashed: for a VeilCore anchor, the 32 raw bytes of the
 * record commitment or batch root (SPEC 3.2) - not their hex text.
 *
 * Checks: (1) the imprint is the hash of `stamped`; (2) the messageDigest signed attribute
 * is the hash of the TSTInfo, and the content types agree; (3) the signature over the
 * signed attributes verifies with the signer certificate's key (RSASSA-PKCS1-v1_5, or
 * ECDSA on P-256/P-384, with SHA-256/384/512; anything else is refused); (4) the signer
 * certificate carries the id-kp-timeStamping extended key usage; and genTime lies within
 * the certificate's validity. It does not check who issued the certificate (`notChecked`).
 */
export const verifyTimestampToken = async (
  token: Uint8Array | string,
  stamped: Uint8Array,
  options: TimestampOptions = {},
): Promise<TimestampVerification> => {
  const result: TimestampVerification = { ok: false, checks: [], notChecked: [...TIMESTAMP_NOT_CHECKED] };
  const add = (ok: boolean, what: string): boolean => {
    result.checks.push({ ok, what });
    return ok;
  };
  try {
    if (typeof token === 'string' && token.length > Math.ceil(MAX_TOKEN_BYTES / 3) * 4 + 4096) {
      add(false, 'the token is larger than any timestamp token should be');
      return result;
    }
    let bytes: Uint8Array;
    try {
      bytes = typeof token === 'string' ? decodeBase64(token) : token;
    } catch {
      add(false, 'the token is not valid base64');
      return result;
    }
    if (bytes.length > MAX_TOKEN_BYTES) {
      add(false, 'the token is larger than any timestamp token should be');
      return result;
    }
    const p = parseToken(bytes);
    add(true, 'the token parses as an RFC 3161 TimeStampToken');
    result.genTime = p.tst.genTime;
    result.hashAlgorithm = p.tst.hashAlgorithm;
    result.serialNumber = p.tst.serialNumber;
    result.policy = p.tst.policy;
    if (p.tst.nonce) result.nonce = p.tst.nonce;

    // (1) The imprint is the hash of what the anchor says it stamps.
    const expected = await digest(p.tst.hashAlgorithm, stamped);
    add(eq(expected, p.tst.hashedMessage), `the imprint is the ${p.tst.hashAlgorithm} of the stamped bytes`);

    // (2) The signed attributes commit to this TSTInfo.
    add(p.eContentType === OID.tstInfo, 'the signed content is a TSTInfo');
    add(p.contentTypeAttr === p.eContentType, 'the contentType signed attribute matches the signed content');
    const tstHash = await digest(p.digestAlgorithm, p.tst.der);
    add(Boolean(p.messageDigestAttr && eq(p.messageDigestAttr, tstHash)), `the messageDigest signed attribute is the ${p.digestAlgorithm} of the TSTInfo`);

    // Find the signer certificate.
    const pool = [...p.certs];
    for (const der of options.certificates ?? []) {
      const n = read(der, 0, der.length);
      if (n.end !== der.length) throw new DerError('a supplied certificate has trailing data');
      pool.push(parseCert(n));
    }
    const sid = p.sid;
    const cert = pool.find((c) => ('ski' in sid ? Boolean(c.ski && eq(c.ski, sid.ski)) : eq(c.issuer, sid.issuer) && eq(c.serial, sid.serial)));
    if (!add(Boolean(cert), 'the signer certificate is present')) return result;
    result.signerSubject = cert!.subject;

    // (3) The signature.
    let hashName: string | undefined;
    let params: RsaHashedImportParams | EcKeyImportParams;
    let sig = p.signature;
    let verifyAlg: AlgorithmIdentifier | EcdsaParams;
    if (p.signatureAlgorithm === OID.rsa || RSA_SIGS[p.signatureAlgorithm]) {
      hashName = RSA_SIGS[p.signatureAlgorithm] ?? p.digestAlgorithm;
      if (cert!.keyAlg !== OID.rsa) throw new Unsupported('the signature algorithm is RSA but the certificate key is not');
      params = { name: 'RSASSA-PKCS1-v1_5', hash: hashName };
      verifyAlg = { name: 'RSASSA-PKCS1-v1_5' };
    } else if (ECDSA_SIGS[p.signatureAlgorithm]) {
      hashName = ECDSA_SIGS[p.signatureAlgorithm];
      const curve = cert!.keyAlg === OID.ec && cert!.curve ? CURVES[cert!.curve] : undefined;
      if (!curve) throw new Unsupported(`the signer key is not ECDSA on P-256 or P-384 (${cert!.curve ?? cert!.keyAlg})`);
      params = { name: 'ECDSA', namedCurve: curve.name };
      verifyAlg = { name: 'ECDSA', hash: hashName };
      sig = ecdsaRaw(sig, curve.size);
    } else {
      throw new Unsupported(`signature algorithm ${p.signatureAlgorithm} is not RSASSA-PKCS1-v1_5 or ECDSA`);
    }
    if (hashName !== p.digestAlgorithm) {
      throw new Unsupported(`the signature hash (${hashName}) differs from the signer digest algorithm (${p.digestAlgorithm})`);
    }
    const s = await subtle();
    const key = await s.importKey('spki', cert!.spki as BufferSource, params, false, ['verify']);
    const good = await s.verify(verifyAlg, key, sig as BufferSource, p.signedAttrs as BufferSource);
    add(good, `the signature over the signed attributes verifies with the signer certificate's key (${params.name}, ${hashName})`);

    // (4) The certificate is marked for time-stamping.
    add(Boolean(cert!.eku?.includes(OID.timeStamping)), 'the signer certificate has the id-kp-timeStamping extended key usage');
    const gt = Date.parse(p.tst.genTime);
    add(
      gt >= Date.parse(cert!.notBefore) && gt <= Date.parse(cert!.notAfter),
      `genTime falls within the signer certificate's validity (${cert!.notBefore} to ${cert!.notAfter})`,
    );
  } catch (e) {
    if (e instanceof Unsupported) add(false, `unsupported: ${e.message}`);
    else if (e instanceof DerError) add(false, `malformed token: ${e.message}`);
    else add(false, `the token could not be checked: ${(e as Error)?.message ?? String(e)}`);
  }
  result.ok = result.checks.length > 0 && result.checks.every((c) => c.ok) && result.checks.some((c) => c.what.startsWith('the signature over'));
  return result;
};
