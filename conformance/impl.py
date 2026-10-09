"""
VeilCore record commitment — reference implementation in Python.

Written from the specification rules, not translated from the JavaScript. That is the
point: if two implementations agree, the specification gives one answer for those inputs. If
they disagree, the specification is wrong and the format cannot be adopted by anyone.

Standard library only. No dependencies, no chain runtime.

SPDX-License-Identifier: Apache-2.0
"""

import hashlib
import json
import sys
import unicodedata


MAX_SAFE = 2**53 - 1


def _number(value):
    """
    Serialise a number per RFC 8785 3.2.2.3: ECMAScript's Number.prototype.toString.

    JSON gives no way to tell 95 from 95.0, and JavaScript cannot, so a float with an
    integral value serialises as an integer. Magnitudes above 2^53 - 1 are invalid (spec
    4.4 rule 8): past it a double no longer holds every integer, and implementations that
    keep big integers exactly disagree with those that round.
    """
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        raise ValueError("non-finite numbers cannot be committed")
    if abs(value) > MAX_SAFE:
        raise ValueError("numbers above 2^53 - 1 in magnitude cannot be committed: use a string (spec 4.4 rule 8)")
    if isinstance(value, int):
        return str(value)
    if value == 0:
        return "0"  # covers -0.0, which ECMAScript writes as 0
    # repr() is the shortest round-trip digits, as ECMAScript's are. Re-lay them out
    # by the ECMAScript rules (Number::toString, steps 6-10).
    sign = "-" if value < 0 else ""
    mantissa, _, exp = repr(abs(value)).partition("e")
    whole, _, frac = mantissa.partition(".")
    digits = (whole + frac).lstrip("0")
    point = len(whole) + (int(exp) if exp else 0)  # position of the point in whole+frac
    lead = len(whole + frac) - len((whole + frac).lstrip("0"))
    n = point - lead  # ECMAScript's n: value = 0.digits * 10^n
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def canonicalise(value):
    """
    Canonical serialisation, per specification section 4.4.

    Follows RFC 8785 where they overlap. Rejects null and post-normalisation key
    collisions rather than resolving them: an implementation that resolves them has to
    choose how, and two implementations choose differently.
    """
    if value is None:
        raise ValueError("null cannot be committed: omit the field instead (spec 4.4 rule 4)")

    if value is True:
        return "true"
    if value is False:
        return "false"

    if isinstance(value, (int, float)):
        return _number(value)

    if isinstance(value, str):
        return _escape(unicodedata.normalize("NFC", value))

    if isinstance(value, list):
        return "[" + ",".join(canonicalise(v) for v in value) + "]"

    if isinstance(value, dict):
        # Omit absent optionals. A present null is rejected above, not dropped.
        present = dict(value)

        # Normalise keys, then detect collisions, then sort. Order matters: two keys
        # differing only by normalisation form are the same key afterwards.
        seen = {}
        for k in present:
            n = unicodedata.normalize("NFC", k)
            if n in seen and seen[n] != k:
                raise ValueError(
                    f'keys "{seen[n]}" and "{k}" are identical after Unicode '
                    "normalisation; the record is invalid (spec 4.4 rule 1)"
                )
            seen[n] = k

        # Python compares strings by code point already, which is what the spec requires.
        parts = [
            _escape(n) + ":" + canonicalise(present[seen[n]])
            for n in sorted(seen)
        ]
        return "{" + ",".join(parts) + "}"

    raise ValueError(f"cannot canonicalise {type(value)}")


def _escape(s):
    """Escape per RFC 8785 3.2.2.2: shortest form, lowercase hex."""
    out = ['"']
    for ch in s:
        c = ord(ch)
        if 0xD800 <= c <= 0xDFFF:
            # An unpaired surrogate has no UTF-8 form (spec 4.4 rule 1).
            raise ValueError("a string with an unpaired surrogate cannot be committed: it is not valid Unicode")
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif c < 0x20:
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def committed_fields(env):
    """
    The fields a commitment covers.

    `anchor` and `terms` are excluded by definition: the anchor is about the commitment
    and cannot be inside it, and terms are issued and revoked after sealing.
    """
    fields = {
        # Absent means empty; an explicit null is refused by canonicalise (spec 4.4 rule 4),
        # never silently read as empty.
        "attestations": env["attestations"] if "attestations" in env else [],
        "commitmentAlgorithm": env["commitmentAlgorithm"],
        "formatVersion": env["formatVersion"],
        "holder": env["holder"],
        "parents": env["parents"] if "parents" in env else [],
        "profile": env["profile"],
        "profileData": env["profileData"],
        "recordId": env["recordId"],
        "sealedAt": env["sealedAt"],
        "subjectType": env["subjectType"],
    }
    # Optional envelope fields are included only when present. Present as null, they reach
    # canonicalise and are refused there, as any other null is: dropping them would make
    # `"supersedes": null` and no supersedes commit alike.
    for key in (
        "extensions", "fieldSchema", "fieldSetRoot", "jurisdictionBindings", "ledgerIdentity", "supersedes",
        # What every subject has, whatever domain it comes from.
        "subject", "identification", "registrations",
    ):
        if key in env:
            fields[key] = env[key]
    return fields


FIELDS_ALGORITHM = "sha256/fields/v1"


def _check_ledger_identity(env):
    """
    `ledgerIdentity` (spec 3.6) is committed, so its shape is checked before anything is
    hashed: `chain` a non-empty string, `identity` and the optional `contractAddress` 64
    lowercase hex characters, and no other key. Present as null is refused, not dropped.
    """
    if "ledgerIdentity" not in env:
        return
    li = env["ledgerIdentity"]
    if not isinstance(li, dict):
        raise ValueError("ledgerIdentity is an object")
    for k in li:
        if k not in ("chain", "contractAddress", "identity"):
            raise ValueError(f"ledgerIdentity has an unknown field: {k}")
    if not isinstance(li.get("chain"), str) or not li["chain"]:
        raise ValueError("ledgerIdentity.chain is a non-empty string")
    if not _is_hex32(li.get("identity")):
        raise ValueError("ledgerIdentity.identity is 64 lowercase hex characters")
    if "contractAddress" in li and not _is_hex32(li["contractAddress"]):
        raise ValueError("ledgerIdentity.contractAddress is 64 lowercase hex characters")


def compute_commitment(env):
    """
    `sha256/canonical-json/v1`: SHA-256 of the canonical JSON of the committed fields.
    `sha256/fields/v1`: H("veilcore:v1:frecord", fieldSetRoot, that same digest), so the
    commitment also binds a field set whose slots can be proved one at a time. The root is
    also inside the committed JSON, so one JSON cannot be paired with two field sets.

    Any other algorithm name is refused rather than guessed.
    """
    _check_ledger_identity(env)
    algorithm = env.get("commitmentAlgorithm")
    if algorithm == "sha256/canonical-json/v1":
        # A field-set binding means nothing under this algorithm. Present at all, even as
        # null, it is refused rather than committed with a root nothing checks.
        if "fieldSchema" in env or "fieldSetRoot" in env:
            raise ValueError("fieldSchema and fieldSetRoot belong only to sha256/fields/v1 records")
        return hashlib.sha256(canonicalise(committed_fields(env)).encode("utf-8")).hexdigest()
    if algorithm != FIELDS_ALGORITHM:
        raise ValueError(f"unsupported commitment algorithm: {algorithm}")
    json_digest = hashlib.sha256(canonicalise(committed_fields(env)).encode("utf-8")).digest()
    if not _is_hex32(env.get("fieldSetRoot")):
        raise ValueError("sha256/fields/v1 needs fieldSetRoot as 64 lowercase hex characters")
    if not _is_hex32(env.get("fieldSchema")):
        raise ValueError("sha256/fields/v1 needs fieldSchema as 64 lowercase hex characters")
    return _h(_tag("veilcore:v1:frecord"), bytes.fromhex(env["fieldSetRoot"]), json_digest).hex()


# Field sets: commitment algorithm sha256/fields/v1.
#
# A record sealed this way commits each of 16 slots as a salted leaf of a four-level
# single root, so a holder can later prove one fact about one slot without disclosing the
# rest. Every hash is SHA-256. Where its input is 32-byte elements, the first is a domain
# tag (UTF-8, zero-padded to 32); a leaf (55 bytes) and the set root (560 bytes) have
# lengths no other hash here has, and the set root carries a 16-byte tag. A slot value is 32 bytes: a number is little-endian in
# bytes 0-7 with byte 8 set to 1 (so 0 is never the same as absent), a text is SHA-256 of
# its NFC UTF-8, and absent is 32 zero bytes. The schema is bound by schemaId, which
# covers its canonical JSON, which slots are comparable, and the threshold k.
#
#   salt_i   = first 23 bytes of H(fsalt, fieldSecret, i)
#   leaf_i   = SHA-256(value_i || salt_i)                      (55 bytes: one block)
#   setRoot  = SHA-256("veilcore:v1:fset" || schemaId || leaf_0 || ... || leaf_15)
#   schemaId = H(fschema, SHA-256(canonical schema), terms)
#   terms    = comparable mask in bytes 0-1, numeric mask in bytes 2-3, k in byte 4
#
# A comparable text slot declares a format (allele-pair, allele, code) and only its
# canonical form is accepted. The record's committed JSON carries fieldSchema and
# fieldSetRoot; a canonical-json/v1 record carrying either is refused.

FIELD_SLOTS = 16


def _is_hex32(s):
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _is_int(n):
    # What JavaScript's Number.isInteger accepts from JSON: 3 and 3.0, never true.
    if isinstance(n, bool):
        return False
    if isinstance(n, int):
        return True
    return isinstance(n, float) and n == n and n not in (float("inf"), float("-inf")) and n == int(n)


def _tag(t):
    b = t.encode("utf-8")
    if len(b) > 32:
        raise ValueError(f"tag too long: {t}")
    return b + bytes(32 - len(b))


def _h(*parts):
    for p in parts:
        if len(p) != 32:
            raise ValueError("every element is 32 bytes")
    return hashlib.sha256(b"".join(parts)).digest()


def _count_bytes(n):
    """A count, mask or index as 32 bytes, little-endian. Not a slot value."""
    if n < 0 or n >= 2**64:
        raise ValueError("a count is 0 to 2^64 - 1")
    return n.to_bytes(8, "little") + bytes(24)


def _slot_value(v):
    if v is None:
        return bytes(32)
    if not isinstance(v, dict) or len(v) != 1:
        raise ValueError("a slot value has exactly one of uint or text")
    if "uint" in v:
        u = v["uint"]
        if not isinstance(u, str) or not u.isascii() or not u.isdigit() or (len(u) > 1 and u[0] == "0"):
            raise ValueError("uint is a decimal string with no leading zeros")
        b = bytearray(_count_bytes(int(u)))
        b[8] = 1
        return bytes(b)
    if "text" in v:
        t = v["text"]
        if not isinstance(t, str):
            raise ValueError("text is a string")
        # An unpaired surrogate has no UTF-8 form: refuse it, as canonicalise does,
        # rather than let an encoder substitute U+FFFD.
        return hashlib.sha256(unicodedata.normalize("NFC", t).encode("utf-8")).digest()
    raise ValueError("a slot value is {uint}, {text} or null")


# Canonical forms for comparable text. Distinctness compares bytes, so one genotype written
# two ways ("180/184" and "184/180") would count as a difference; a comparable text slot
# therefore declares a format and only its canonical form is accepted.
#   allele-pair  two allele sizes, decimal, at most 9 digits, no leading zeros, smaller first
#   allele       one allele size
#   code         1-64 of A-Z 0-9 . _ -, starting with a letter or digit
FIELD_FORMATS = ("allele-pair", "allele", "code")
_DIGITS = "0123456789"
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _is_allele(t):
    return 1 <= len(t) <= 9 and all(c in _DIGITS for c in t) and (t == "0" or t[0] != "0")


def _check_format(fmt, t):
    if not isinstance(t, str):
        raise ValueError("text is a string")
    if fmt == "allele":
        ok = _is_allele(t)
    elif fmt == "allele-pair":
        a, sep, b = t.partition("/")
        ok = sep == "/" and _is_allele(a) and _is_allele(b)
        if ok and int(a) > int(b):
            raise ValueError(f"an allele pair is written smaller first: {t!r}")
    elif fmt == "code":
        ok = (1 <= len(t) <= 64 and t[0] in _UPPER + _DIGITS
              and all(c in _UPPER + _DIGITS + "._-" for c in t))
    else:
        raise ValueError(f"unknown format: {fmt}")
    if not ok:
        raise ValueError(f"not in {fmt} form: {t!r}")


def _schema_masks(schema):
    """Check a schema document and return its comparable and numeric masks."""
    if not isinstance(schema, dict) or not isinstance(schema.get("slots"), list):
        raise ValueError("a schema lists its slots")
    if not isinstance(schema.get("id"), str) or not schema["id"]:
        raise ValueError("a schema has an id")
    if not isinstance(schema.get("title"), str):
        raise ValueError("a schema has a title")
    comparable = [False] * FIELD_SLOTS
    numeric = [False] * FIELD_SLOTS
    seen = set()
    for s in schema["slots"]:
        if not isinstance(s, dict):
            raise ValueError("a slot entry is an object")
        n = s.get("slot")
        if not _is_int(n) or n < 0 or n >= FIELD_SLOTS:
            raise ValueError(f"slot out of range: {n}")
        n = int(n)
        if n in seen:
            raise ValueError(f"slot {n} is listed twice")
        seen.add(n)
        if s.get("type") not in ("uint", "text"):
            raise ValueError(f"slot {n} has an unknown type")
        if not isinstance(s.get("path"), str) or not s["path"]:
            raise ValueError(f"slot {n} has no path")
        # Present means present: a null unit, scale, comparable or format is refused, not
        # read as absent.
        if "unit" in s and not isinstance(s["unit"], str):
            raise ValueError(f"slot {n}: unit is a string")
        if "scale" in s and (not _is_int(s["scale"]) or s["scale"] < 1):
            raise ValueError(f"slot {n}: scale is a positive integer")
        if "comparable" in s and not isinstance(s["comparable"], bool):
            raise ValueError(f"slot {n}: comparable is true or false")
        if "format" in s and (s["type"] != "text" or not isinstance(s["format"], str) or s["format"] not in FIELD_FORMATS):
            raise ValueError(f"slot {n}: format is allele-pair, allele or code, on a text slot")
        if s.get("comparable") and s["type"] == "text" and "format" not in s:
            raise ValueError(f"slot {n}: a comparable text slot declares a format")
        comparable[n] = s.get("comparable") is True
        numeric[n] = s["type"] == "uint"
    return comparable, numeric


def _terms_bytes(comparable, numeric, k):
    """The schema's terms in one 32-byte element (masks little-endian, slot i is bit i)."""
    c = sum(1 << i for i, b in enumerate(comparable) if b)
    n = sum(1 << i for i, b in enumerate(numeric) if b)
    return c.to_bytes(2, "little") + n.to_bytes(2, "little") + bytes([k]) + bytes(27)


def field_set(job):
    """Seal 16 typed slot values under a schema and report everything public or checkable."""
    if not isinstance(job, dict):
        raise ValueError("a field set job is an object")
    values = job.get("values")
    if not isinstance(values, list) or len(values) != FIELD_SLOTS:
        raise ValueError("a field set has 16 slots")
    if not _is_hex32(job.get("fieldSecret")):
        raise ValueError("fieldSecret is 64 lowercase hex characters")
    schema = job.get("schema")
    mask, numeric = _schema_masks(schema)
    k = schema.get("k")
    if not _is_int(k) or k < 1 or k > FIELD_SLOTS:
        raise ValueError("k is 1 to 16")
    if sum(mask) < k:
        raise ValueError("k is more than the number of comparable slots")
    doc_digest = hashlib.sha256(canonicalise(schema).encode("utf-8")).digest()
    # The masks and k are inside the id so a claim cannot choose them; the numeric mask lets
    # the claims contract refuse a range claim on a slot that is not a number.
    schema_id = _h(_tag("veilcore:v1:fschema"), doc_digest, _terms_bytes(mask, numeric, int(k)))

    # Each value must match its slot's declared type, and a slot the schema does not
    # describe must be empty: otherwise a text hash could sit in a number slot and a range
    # claim would run over it. A text value in a slot with a format must be in that form.
    type_of = {int(s["slot"]): s["type"] for s in schema["slots"]}
    format_of = {int(s["slot"]): s.get("format") for s in schema["slots"]}
    for i, v in enumerate(values):
        if v is None:
            continue
        if i not in type_of:
            raise ValueError(f"slot {i} is not described by the schema, so it must be empty")
        kind = "uint" if isinstance(v, dict) and "uint" in v else "text" if isinstance(v, dict) and "text" in v else None
        if kind != type_of[i]:
            raise ValueError(f"slot {i} holds {type_of[i]} values")
        if format_of[i] is not None:
            _check_format(format_of[i], v["text"])
    slot_values = [_slot_value(v) for v in values]
    secret = bytes.fromhex(job["fieldSecret"])
    salts = [_h(_tag("veilcore:v1:fsalt"), secret, _count_bytes(i))[:23] for i in range(FIELD_SLOTS)]
    leaves = [hashlib.sha256(v + salts[i]).digest() for i, v in enumerate(slot_values)]
    set_root = hashlib.sha256(b"veilcore:v1:fset" + schema_id + b"".join(leaves)).digest()

    return {
        "schemaDocumentDigest": doc_digest.hex(),
        "schemaId": schema_id.hex(),
        "slotValues": [v.hex() for v in slot_values],
        "salts": [s.hex() for s in salts],
        "leaves": [l.hex() for l in leaves],
        "setRoot": set_root.hex(),
    }


def attestation_payload(a):
    """The bytes an attester signs, per specification section 7.

    The attester's identity goes in whole, not by its key alone. Signing the key
    and leaving displayName, role and accreditation outside it lets anyone holding
    a genuine attestation rewrite them while the signature still verifies, and
    section 7.2 then reports a strength tier the attester never claimed.
    """
    att = a["attester"]
    attester = {"publicKey": att["publicKey"]}
    for key in ("displayName", "role", "accreditation"):
        if att.get(key) is not None:
            attester[key] = att[key]

    return canonicalise({
        "attestationId": a["attestationId"],
        "attester": attester,
        "documentHash": a["documentHash"],
        "hashAlgorithm": a["hashAlgorithm"],
        "issuedAt": a["issuedAt"],
        "subjectCommitment": a["subjectCommitment"],
        "type": a["type"],
    })

def hash_leaf(commitment):
    """Leaves and interior nodes are domain-separated so a leaf can never be
    presented as an interior node."""
    return hashlib.sha256(("00" + commitment).encode("utf-8")).hexdigest()


def hash_node(left, right):
    return hashlib.sha256(("01" + left + right).encode("utf-8")).hexdigest()


def fold_proof(commitment, path):
    """Fold an inclusion path (spec 5.4). Every operand is 64 lowercase hex characters
    (spec 5.1, 5.2) and every direction flag a real boolean: a sibling of any other length
    makes "01" + left + right ambiguous, and Python's truthiness would read "false" or 1
    as a direction where the TypeScript and Rust implementations refuse the step."""
    if not _is_hex32(commitment):
        raise ValueError("a commitment is 64 lowercase hex characters (spec 5.1)")
    if not isinstance(path, list):
        raise ValueError("a proof path is a list (spec 5.4)")
    if len(path) > 64:
        raise ValueError("proof path exceeds maximum depth (spec 5.4)")
    for step in path:
        if not isinstance(step, dict) or not _is_hex32(step.get("sibling")) or not isinstance(step.get("siblingIsLeft"), bool):
            raise ValueError("each proof step is a sibling of 64 lowercase hex characters and a boolean siblingIsLeft (spec 5.4)")
    node = hash_leaf(commitment)
    for step in path:
        if step["siblingIsLeft"]:
            node = hash_node(step["sibling"], node)
        else:
            node = hash_node(node, step["sibling"])
    return node


def dna_pair_binding(report_hash, identity, salt):
    """The value a ledger pairing publishes for a report (spec 3.7):
    H("veilcore:v1:dnapair", reportHash, identity, salt), each input 64 lowercase hex."""
    for name, v in (("reportHash", report_hash), ("identity", identity), ("salt", salt)):
        if not _is_hex32(v):
            raise ValueError(f"{name} must be 64 lowercase hex characters (spec 3.7)")
    return _h(_tag("veilcore:v1:dnapair"), bytes.fromhex(report_hash), bytes.fromhex(identity), bytes.fromhex(salt)).hex()


def main():
    job = json.loads(sys.stdin.read())
    op = job["op"]
    if op == "canonicalise":
        print(json.dumps({"result": canonicalise(job["input"])}))
    elif op == "attestationPayload":
        print(json.dumps({"result": attestation_payload(job["input"])}), flush=True)
    elif op == "commit":
        print(json.dumps({"result": compute_commitment(job["input"])}))
    elif op == "fieldSet":
        print(json.dumps({"result": field_set(job["input"])}))
    elif op == "fold":
        print(json.dumps({"result": fold_proof(job["input"]["commitment"], job["input"]["path"])}))
    elif op == "dnaPair":
        i = job["input"]
        print(json.dumps({"result": dna_pair_binding(i["reportHash"], i["identity"], i["salt"])}))
    else:
        print(json.dumps({"error": f"unknown op {op}"}))
        sys.exit(1)

if __name__ == "__main__":
    main()
