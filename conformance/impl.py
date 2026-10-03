"""
VeilCore record commitment — reference implementation in Python.

Written from the specification rules, not translated from the JavaScript. That is the
point: if two independent implementations agree, the specification is unambiguous. If
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
        "attestations": env.get("attestations") or [],
        "commitmentAlgorithm": env["commitmentAlgorithm"],
        "formatVersion": env["formatVersion"],
        "holder": env["holder"],
        "parents": env.get("parents") or [],
        "profile": env["profile"],
        "profileData": env["profileData"],
        "recordId": env["recordId"],
        "sealedAt": env["sealedAt"],
        "subjectType": env["subjectType"],
    }
    # Optional envelope fields are included only when present, never as null.
    for key in (
        "extensions", "fieldSchema", "jurisdictionBindings", "supersedes",
        # What every subject has, whatever domain it comes from.
        "subject", "identification", "registrations",
    ):
        if env.get(key) is not None:
            fields[key] = env[key]
    return fields


FIELDS_ALGORITHM = "sha256/fields/v1"


def compute_commitment(env):
    """
    `sha256/canonical-json/v1`: SHA-256 of the canonical JSON of the committed fields.
    `sha256/fields/v1`: H("veilcore:v1:frecord", fieldSetRoot, that same digest), so the
    commitment also binds a field set whose slots can be proved one at a time.
    """
    json_digest = hashlib.sha256(canonicalise(committed_fields(env)).encode("utf-8")).digest()
    if env.get("commitmentAlgorithm") != FIELDS_ALGORITHM:
        return json_digest.hex()
    if not _is_hex32(env.get("fieldSetRoot")):
        raise ValueError("sha256/fields/v1 needs fieldSetRoot as 64 lowercase hex characters")
    if not _is_hex32(env.get("fieldSchema")):
        raise ValueError("sha256/fields/v1 needs fieldSchema as 64 lowercase hex characters")
    return _h(_tag("veilcore:v1:frecord"), bytes.fromhex(env["fieldSetRoot"]), json_digest).hex()


# Field sets: commitment algorithm sha256/fields/v1.
#
# A record sealed this way commits each of 16 slots as a salted leaf of a four-level
# binary tree, so a holder can later prove one fact about one slot without disclosing the
# rest. Every hash is SHA-256 over 32-byte elements, the first of which is a domain tag
# (UTF-8, zero-padded to 32). A slot value is 32 bytes: a number is little-endian in
# bytes 0-7 with byte 8 set to 1 (so 0 is never the same as absent), a text is SHA-256 of
# its NFC UTF-8, and absent is 32 zero bytes. The schema is bound by schemaId, which
# covers its canonical JSON, which slots are comparable, and the threshold k.
#
#   salt_i  = H(fsalt, fieldSecret, i)        leaf = H(field, value, salt)
#   node    = H(fnode, left, right)           setRoot = H(fset, schemaId, tree root)
#   schemaId = H(fschema, SHA-256(canonical schema), comparable mask, k)

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


def _comparable_mask(schema):
    if not isinstance(schema, dict) or not isinstance(schema.get("slots"), list):
        raise ValueError("a schema lists its slots")
    mask = [False] * FIELD_SLOTS
    seen = set()
    for s in schema["slots"]:
        if not isinstance(s, dict):
            raise ValueError("a slot is an object")
        n = s.get("slot")
        if not _is_int(n) or n < 0 or n >= FIELD_SLOTS:
            raise ValueError(f"slot out of range: {n}")
        n = int(n)
        if n in seen:
            raise ValueError(f"slot {n} is listed twice")
        seen.add(n)
        if s.get("type") not in ("uint", "text"):
            raise ValueError(f"slot {n} has an unknown type")
        if "comparable" in s and not isinstance(s["comparable"], bool):
            raise ValueError(f"slot {n}: comparable is true or false")
        if s.get("comparable"):
            mask[n] = True
    return mask


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
    mask = _comparable_mask(schema)
    k = schema.get("k")
    if not _is_int(k) or k < 1 or k > FIELD_SLOTS:
        raise ValueError("k is 1 to 16")
    if sum(mask) < k:
        raise ValueError("k is more than the number of comparable slots")
    doc_digest = hashlib.sha256(canonicalise(schema).encode("utf-8")).digest()
    mask_bytes = _count_bytes(sum(1 << i for i, b in enumerate(mask) if b))
    schema_id = _h(_tag("veilcore:v1:fschema"), doc_digest, mask_bytes, _count_bytes(int(k)))

    # Each value must match its slot's declared type, and a slot the schema does not
    # describe must be empty: otherwise a text hash could sit in a number slot and a range
    # claim would run over it.
    type_of = {int(s["slot"]): s["type"] for s in schema["slots"]}
    for i, v in enumerate(values):
        if v is None:
            continue
        if i not in type_of:
            raise ValueError(f"slot {i} is not described by the schema, so it must be empty")
        kind = "uint" if isinstance(v, dict) and "uint" in v else "text" if isinstance(v, dict) and "text" in v else None
        if kind != type_of[i]:
            raise ValueError(f"slot {i} holds {type_of[i]} values")
    slot_values = [_slot_value(v) for v in values]
    secret = bytes.fromhex(job["fieldSecret"])
    salts = [_h(_tag("veilcore:v1:fsalt"), secret, _count_bytes(i)) for i in range(FIELD_SLOTS)]

    levels = [[_h(_tag("veilcore:v1:field"), v, salts[i]) for i, v in enumerate(slot_values)]]
    while len(levels[-1]) > 1:
        prev = levels[-1]
        levels.append([_h(_tag("veilcore:v1:fnode"), prev[i], prev[i + 1]) for i in range(0, len(prev), 2)])
    set_root = _h(_tag("veilcore:v1:fset"), schema_id, levels[-1][0])

    opens = job.get("open")
    if opens is None:
        opens = []
    if not isinstance(opens, list):
        raise ValueError("open is a list of slots")
    openings = []
    for slot in opens:
        if not _is_int(slot) or slot < 0 or slot >= FIELD_SLOTS:
            raise ValueError("slot is 0 to 15")
        i = int(slot)
        siblings, bits = [], []
        for level in range(4):
            bits.append(i & 1 == 1)
            siblings.append(levels[level][i ^ 1].hex())
            i >>= 1
        openings.append({"slot": int(slot), "siblings": siblings, "bits": bits})

    return {
        "schemaDocumentDigest": doc_digest.hex(),
        "schemaId": schema_id.hex(),
        "slotValues": [v.hex() for v in slot_values],
        "salts": [s.hex() for s in salts],
        "setRoot": set_root.hex(),
        "openings": openings,
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
    if len(path) > 64:
        raise ValueError("proof path exceeds maximum depth (spec 5.1)")
    node = hash_leaf(commitment)
    for step in path:
        if step["siblingIsLeft"]:
            node = hash_node(step["sibling"], node)
        else:
            node = hash_node(node, step["sibling"])
    return node
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
    else:
        print(json.dumps({"error": f"unknown op {op}"}))
        sys.exit(1)

if __name__ == "__main__":
    main()
