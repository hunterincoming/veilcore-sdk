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


# A record that names its own key (spec 3.6.1). H as in 3.7 and 4.5.
KEY_BOUND_ALGORITHM = "sha256/key-bound/v1"


def _key_h(tag, *named):
    for name, v in named:
        if not _is_hex32(v):
            raise ValueError(f"{name} must be 64 lowercase hex characters (spec 3.6.1)")
    return _h(_tag(tag), *(bytes.fromhex(v) for _, v in named)).hex()


def identity_from_secret(record_secret):
    """The record's ledger identity: H("veilcore:v1:commit", recordSecret), the contract's commit()."""
    return _key_h("veilcore:v1:commit", ("recordSecret", record_secret))


def key_salt_of(record_secret):
    """The key's salt: H("veilcore:v1:keysalt", recordSecret). Never on the record."""
    return _key_h("veilcore:v1:keysalt", ("recordSecret", record_secret))


def key_binding_of(identity, key_salt):
    """The committed field: H("veilcore:v1:keybind", identity, keySalt)."""
    return _key_h("veilcore:v1:keybind", ("identity", identity), ("keySalt", key_salt))


def key_bound_fingerprint(key_binding, content_hash):
    """A key-bound fingerprint: H("veilcore:v1:keyrecord", keyBinding, contentHash)."""
    return _key_h("veilcore:v1:keyrecord", ("keyBinding", key_binding), ("contentHash", content_hash))


def record_fingerprint(fields):
    """The fingerprint of committed JSON anchored on its own (spec 3.6.1), hashed as given.
    A keyBinding that is present is sealed and must be 64 lowercase hex characters; fields
    without one keep sha256/canonical-json/v1, whose fingerprint is the content hash.
    Returns {"algorithm", "contentHash", "fingerprint"}."""
    if not isinstance(fields, dict):
        raise ValueError("the committed fields are a JSON object")
    if "keyBinding" in fields and not _is_hex32(fields["keyBinding"]):
        raise ValueError("keyBinding must be 64 lowercase hex characters (spec 3.6.1)")
    # A field set comes whole, and the content hash is then the 4.5 commitment over it.
    with_set = "fieldSchema" in fields or "fieldSetRoot" in fields
    if with_set and not (_is_hex32(fields.get("fieldSchema")) and _is_hex32(fields.get("fieldSetRoot"))):
        raise ValueError("fieldSchema and fieldSetRoot come together, each 64 lowercase hex characters (spec 4.5)")
    content = hashlib.sha256(canonicalise(fields).encode("utf-8")).hexdigest()
    if with_set:
        content = _key_h("veilcore:v1:frecord", ("fieldSetRoot", fields["fieldSetRoot"]), ("jsonDigest", content))
    if "keyBinding" not in fields:
        algorithm = "sha256/fields/v1" if with_set else "sha256/canonical-json/v1"
        return {"algorithm": algorithm, "contentHash": content, "fingerprint": content}
    return {
        "algorithm": KEY_BOUND_ALGORITHM,
        "contentHash": content,
        "fingerprint": key_bound_fingerprint(fields["keyBinding"], content),
    }


def key_matches_record(identity, fingerprint, key_salt, content_hash):
    """Is this identity the key the record named when it was sealed? Recomputes
    H(keyrecord, H(keybind, identity, keySalt), contentHash) and compares. Any input that
    is not 64 lowercase hex characters does not match; it is not an error."""
    if not all(_is_hex32(v) for v in (identity, fingerprint, key_salt, content_hash)):
        return False
    return key_bound_fingerprint(key_binding_of(identity, key_salt), content_hash) == fingerprint


# ---- animal records (spec 11.8, final) ----------------------------------------------------

ANIMAL_PROFILE = "veilcore/profile/animal-individual/v1"
_ANIMAL_REQUIRED = (
    "breed", "breeder", "dateOfBirth", "herd", "idScheme", "individualId", "loggedAt", "name",
    "nonce", "notes", "parents", "photoFingerprints", "profile", "sex", "species",
)
_ANIMAL_LINES = ("species", "breed", "name", "individualId", "idScheme", "breeder", "herd")
_PARENT_KEYS = ("role", "name", "individualId", "recordId")
# White space as ECMAScript's String.prototype.trim() strips it, so "no white space at either
# end" means the same here as in the TypeScript implementation.
_JS_SPACE = set("\t\n\v\f\r \u00a0\u1680\u2028\u2029\u202f\u205f\u3000\ufeff") | {
    chr(c) for c in range(0x2000, 0x200B)
}


def _one_line_problem(what, v):
    if not isinstance(v, str):
        return f"{what} must be text"
    if len(v) > 200:
        return f"{what} must be at most 200 characters"
    if any(unicodedata.category(ch) == "Cc" for ch in v):
        return f"{what} must be one line, with no tabs or control characters"
    if v and (v[0] in _JS_SPACE or v[-1] in _JS_SPACE):
        return f"{what} must not start or end with a space"
    return None


def _calendar_date(v):
    if not isinstance(v, str) or len(v) != 10 or v[4] != "-" or v[7] != "-":
        return False
    y, m, d = v[0:4], v[5:7], v[8:10]
    if not (y.isascii() and y.isdigit() and m.isascii() and m.isdigit() and d.isascii() and d.isdigit()):
        return False
    y, m, d = int(y), int(m), int(d)
    if not 1 <= m <= 12:
        return False
    days = [31, 29 if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return 1 <= d <= days[m - 1]


def _is_whole(n):
    return isinstance(n, int) and not isinstance(n, bool) and 0 <= n <= MAX_SAFE or (
        isinstance(n, float) and n.is_integer() and 0 <= n <= MAX_SAFE
    )


def animal_problems(fields):
    """What is wrong with an animal record's committed fields (spec 11.8); [] when nothing is."""
    if not isinstance(fields, dict):
        return ["the fields must be an object"]
    f = fields
    out = []
    if f.get("profile") != ANIMAL_PROFILE:
        out.append(f"profile must be {ANIMAL_PROFILE}")
    out += [f"{k} is missing" for k in _ANIMAL_REQUIRED if k not in f]
    out += [f"{k} is not a field of this profile" for k in f if k not in _ANIMAL_REQUIRED and k != "keyBinding"]
    for k in _ANIMAL_LINES:
        if k in f:
            p = _one_line_problem(k, f[k])
            if p:
                out.append(p)
    if "notes" in f and (not isinstance(f["notes"], str) or len(f["notes"]) > 20000):
        out.append("notes must be text of at most 20000 characters")
    text = lambda k: f[k] if isinstance(f.get(k), str) else ""
    if "species" in f and text("species") == "":
        out.append("species must not be empty")
    if "breeder" in f and text("breeder") == "":
        out.append("breeder must not be empty")
    if "name" in f and "individualId" in f and text("name") == "" and text("individualId") == "":
        out.append("a name or an individual ID is needed")
    if text("individualId") != "" and "idScheme" in f and text("idScheme") == "":
        out.append("idScheme must say which ID scheme the individual ID belongs to")
    if text("idScheme") != "" and "individualId" in f and text("individualId") == "":
        out.append("idScheme is given but individualId is empty")
    if "sex" in f and f["sex"] not in ("female", "male", "unknown"):
        out.append("sex must be female, male or unknown")
    if "dateOfBirth" in f and f["dateOfBirth"] != "" and not _calendar_date(f["dateOfBirth"]):
        out.append("dateOfBirth must be empty or a date written YYYY-MM-DD")
    if "loggedAt" in f and not _is_whole(f["loggedAt"]):
        out.append("loggedAt must be a whole number of milliseconds, 0 or more")
    nonce = f.get("nonce")
    if "nonce" in f and not (
        isinstance(nonce, str) and 64 <= len(nonce) <= 128 and len(nonce) % 2 == 0 and all(c in "0123456789abcdef" for c in nonce)
    ):
        out.append("nonce must be 32 to 64 bytes of lowercase hex")
    if "keyBinding" in f and not _is_hex32(f["keyBinding"]):
        out.append("keyBinding must be 64 lowercase hex characters")
    photos = f.get("photoFingerprints")
    if "photoFingerprints" in f:
        if not isinstance(photos, list) or len(photos) > 500:
            out.append("photoFingerprints must be a list of at most 500")
        elif not all(_is_hex32(p) for p in photos):
            out.append("each photo fingerprint must be 64 lowercase hex characters")
    if "parents" in f:
        out += _parent_problems(f["parents"])
    return out


def _record_id(v):
    if not isinstance(v, str) or not 1 <= len(v) <= 128:
        return False
    ok = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    return v[0] in ok and all(c in ok or c in "._:-" for c in v)


def _parent_problems(parents):
    if not isinstance(parents, list):
        return ["parents must be a list"]
    if len(parents) > 2:
        return ["parents may name a sire and a dam, nothing more"]
    out, roles = [], []
    for i, p in enumerate(parents):
        at = f"parent {i + 1}"
        if not isinstance(p, dict):
            out.append(f"{at} must be an object")
            continue
        out += [f"{at}: {k} is not a parent field" for k in p if k not in _PARENT_KEYS]
        if p.get("role") in ("sire", "dam"):
            roles.append(p["role"])
        else:
            out.append(f"{at}: role must be sire or dam")
        for k in ("name", "individualId"):
            if k not in p:
                out.append(f"{at}: {k} is missing")
            else:
                pr = _one_line_problem(f"{at}: {k}", p[k])
                if pr:
                    out.append(pr)
        if "recordId" in p and not _record_id(p["recordId"]):
            out.append(f"{at}: recordId is not a record id")
        if "recordId" not in p and p.get("name") == "" and p.get("individualId") == "":
            out.append(f"{at}: needs a name, an individual ID or a linked record")
    if len(roles) == 2 and roles[0] == roles[1]:
        out.append("parents may name one sire and one dam")
    elif len(roles) == 2 and roles[0] != "sire":
        out.append("the sire comes before the dam")
    return out


def animal_record_fingerprint(fields):
    """An animal record's fingerprint (spec 11.8): its form checked, then exactly
    record_fingerprint. Raises for fields not in the profile's form."""
    problems = animal_problems(fields)
    if problems:
        raise ValueError("not a valid animal record: " + "; ".join(problems))
    return record_fingerprint(fields)


# ---- strain and line records (spec 11.9) -------------------------------------------------

STRAIN_PROFILE = "veilcore/profile/strain/v1"
_STRAIN_GROUPS = (
    "bacterium", "archaeon", "yeast", "filamentous-fungus", "microalga", "protist", "virus",
    "cell-line", "insect", "other",
)
_STRAIN_REQUIRED = (
    "deposits", "designation", "generation", "group", "loggedAt", "madeOn", "maker", "method",
    "name", "nonce", "notes", "parents", "photoFingerprints", "profile", "species",
)
_STRAIN_LINES = ("species", "name", "designation", "method", "generation", "maker")
_STRAIN_PARENT_KEYS = ("name", "deposit", "recordId")


def strain_problems(fields):
    """What is wrong with a strain record's committed fields (spec 11.9); [] when nothing is."""
    if not isinstance(fields, dict):
        return ["the fields must be an object"]
    f = fields
    out = []
    if f.get("profile") != STRAIN_PROFILE:
        out.append(f"profile must be {STRAIN_PROFILE}")
    out += [f"{k} is missing" for k in _STRAIN_REQUIRED if k not in f]
    out += [f"{k} is not a field of this profile" for k in f if k not in _STRAIN_REQUIRED and k != "keyBinding"]
    for k in _STRAIN_LINES:
        if k in f:
            p = _one_line_problem(k, f[k])
            if p:
                out.append(p)
    text = lambda k: f[k] if isinstance(f.get(k), str) else ""
    if "species" in f and text("species") == "":
        out.append("species must not be empty")
    if "maker" in f and text("maker") == "":
        out.append("maker must not be empty")
    if "name" in f and "designation" in f and text("name") == "" and text("designation") == "":
        out.append("a name or a designation is needed")
    if "group" in f and f["group"] not in _STRAIN_GROUPS:
        out.append("group must be one of " + ", ".join(_STRAIN_GROUPS))
    if "deposits" in f:
        d = f["deposits"]
        if not isinstance(d, list) or len(d) > 8:
            out.append("deposits must be a list of at most 8")
        else:
            for i, x in enumerate(d):
                p = _one_line_problem(f"deposit {i + 1}", x)
                if p:
                    out.append(p)
                elif x == "":
                    out.append(f"deposit {i + 1} must not be empty")
            if all(isinstance(x, str) for x in d) and len(set(d)) != len(d):
                out.append("each deposit is listed once")
    if "notes" in f and (not isinstance(f["notes"], str) or len(f["notes"]) > 20000):
        out.append("notes must be text of at most 20000 characters")
    if "madeOn" in f and f["madeOn"] != "" and not _calendar_date(f["madeOn"]):
        out.append("madeOn must be empty or a date written YYYY-MM-DD")
    if "loggedAt" in f and not _is_whole(f["loggedAt"]):
        out.append("loggedAt must be a whole number of milliseconds, 0 or more")
    nonce = f.get("nonce")
    if "nonce" in f and not (
        isinstance(nonce, str) and 64 <= len(nonce) <= 128 and len(nonce) % 2 == 0 and all(c in "0123456789abcdef" for c in nonce)
    ):
        out.append("nonce must be 32 to 64 bytes of lowercase hex")
    if "keyBinding" in f and not _is_hex32(f["keyBinding"]):
        out.append("keyBinding must be 64 lowercase hex characters")
    photos = f.get("photoFingerprints")
    if "photoFingerprints" in f:
        if not isinstance(photos, list) or len(photos) > 500:
            out.append("photoFingerprints must be a list of at most 500")
        elif not all(_is_hex32(p) for p in photos):
            out.append("each photo code must be 64 lowercase hex characters")
    if "parents" in f:
        out += _strain_parent_problems(f["parents"])
    return out


def _strain_parent_problems(parents):
    if not isinstance(parents, list):
        return ["parents must be a list"]
    if len(parents) > 2:
        return ["parents may name at most two parent strains"]
    out = []
    for i, p in enumerate(parents):
        at = f"parent {i + 1}"
        if not isinstance(p, dict):
            out.append(f"{at} must be an object")
            continue
        out += [f"{at}: {k} is not a parent field" for k in p if k not in _STRAIN_PARENT_KEYS]
        for k in ("name", "deposit"):
            if k not in p:
                out.append(f"{at}: {k} is missing")
            else:
                pr = _one_line_problem(f"{at}: {k}", p[k])
                if pr:
                    out.append(pr)
        if "recordId" in p and not _record_id(p["recordId"]):
            out.append(f"{at}: recordId is not a record id")
        if "recordId" not in p and p.get("name") == "" and p.get("deposit") == "":
            out.append(f"{at}: needs a name, a deposit number or a linked record")
    return out


def strain_record_fingerprint(fields):
    """A strain record's fingerprint (spec 11.9): its form checked, then exactly
    record_fingerprint. Raises for fields not in the profile's form."""
    problems = strain_problems(fields)
    if problems:
        raise ValueError("not a valid strain record: " + "; ".join(problems))
    return record_fingerprint(fields)


# ---- document records (spec 11.11, final) -------------------------------------------------

DOCUMENT_PROFILE = "veilcore/profile/document/v1"
_DOCUMENT_TYPES = (
    "permit", "certificate-of-analysis", "lab-report", "contract", "protocol", "transport",
    "invoice", "other",
)
_DOCUMENT_REQUIRED = (
    "about", "files", "holder", "issued", "issuer", "loggedAt", "nonce", "notes", "profile",
    "reference", "title", "type",
)
_DOCUMENT_LINES = ("title", "issuer", "reference", "holder")


def document_problems(fields):
    """What is wrong with a document record's committed fields (spec 11.11); [] when nothing is."""
    if not isinstance(fields, dict):
        return ["the fields must be an object"]
    f = fields
    out = []
    if f.get("profile") != DOCUMENT_PROFILE:
        out.append(f"profile must be {DOCUMENT_PROFILE}")
    out += [f"{k} is missing" for k in _DOCUMENT_REQUIRED if k not in f]
    out += [f"{k} is not a field of this profile" for k in f if k not in _DOCUMENT_REQUIRED and k not in ("keyBinding", "fieldSchema", "fieldSetRoot")]
    for k in _DOCUMENT_LINES:
        if k in f:
            p = _one_line_problem(k, f[k])
            if p:
                out.append(p)
    if f.get("title") == "":
        out.append("title must not be empty")
    if f.get("holder") == "":
        out.append("holder must not be empty")
    if "type" in f and f["type"] not in _DOCUMENT_TYPES:
        out.append("type must be one of " + ", ".join(_DOCUMENT_TYPES))
    if "files" in f:
        out += _document_file_problems(f["files"])
    if "about" in f:
        out += _document_about_problems(f["about"])
    if "notes" in f and (not isinstance(f["notes"], str) or len(f["notes"]) > 20000):
        out.append("notes must be text of at most 20000 characters")
    if "issued" in f and f["issued"] != "" and not _calendar_date(f["issued"]):
        out.append("issued must be empty or a date written YYYY-MM-DD")
    if "loggedAt" in f and not _is_whole(f["loggedAt"]):
        out.append("loggedAt must be a whole number of milliseconds, 0 or more")
    nonce = f.get("nonce")
    if "nonce" in f and not (
        isinstance(nonce, str) and 64 <= len(nonce) <= 128 and len(nonce) % 2 == 0 and all(c in "0123456789abcdef" for c in nonce)
    ):
        out.append("nonce must be 32 to 64 bytes of lowercase hex")
    if "keyBinding" in f and not _is_hex32(f["keyBinding"]):
        out.append("keyBinding must be 64 lowercase hex characters")
    # A field set (spec 4.5): its schema id and root come together, or neither is there.
    if ("fieldSchema" in f) != ("fieldSetRoot" in f):
        out.append("fieldSchema and fieldSetRoot come together, or neither")
    for k in ("fieldSchema", "fieldSetRoot"):
        if k in f and not _is_hex32(f[k]):
            out.append(f"{k} must be 64 lowercase hex characters")
    return out


def _document_file_problems(files):
    if not isinstance(files, list):
        return ["files must be a list"]
    if len(files) < 1:
        return ["a document needs at least one file"]
    if len(files) > 20:
        return ["files may list at most 20"]
    out = []
    for i, x in enumerate(files):
        at = f"file {i + 1}"
        if not isinstance(x, dict):
            out.append(f"{at} must be an object")
            continue
        out += [f"{at}: {k} is not a file field" for k in x if k not in ("name", "sha256", "size")]
        if "name" not in x:
            out.append(f"{at}: name is missing")
        else:
            p = _one_line_problem(f"{at}: name", x["name"])
            if p:
                out.append(p)
            elif x["name"] == "":
                out.append(f"{at}: name must not be empty")
        if not _is_hex32(x.get("sha256")):
            out.append(f"{at}: sha256 must be 64 lowercase hex characters")
        if not _is_whole(x.get("size")):
            out.append(f"{at}: size must be a whole number of bytes, 0 or more")
    shas = [repr(x.get("sha256")) if isinstance(x, dict) else None for x in files]
    if len(set(shas)) != len(shas):
        out.append("each file is listed once (no two with the same SHA-256)")
    return out


def _document_about_problems(about):
    if not isinstance(about, list):
        return ["about must be a list"]
    if len(about) > 20:
        return ["about may name at most 20 records"]
    out = []
    for i, a in enumerate(about):
        at = f"about {i + 1}"
        if not isinstance(a, dict):
            out.append(f"{at} must be an object")
            continue
        out += [f"{at}: {k} is not an about field" for k in a if k not in ("name", "recordId")]
        if "name" not in a:
            out.append(f"{at}: name is missing")
        else:
            p = _one_line_problem(f"{at}: name", a["name"])
            if p:
                out.append(p)
        if "recordId" in a and not _record_id(a["recordId"]):
            out.append(f"{at}: recordId is not a record id")
        if "recordId" not in a and a.get("name") == "":
            out.append(f"{at}: needs a name or a linked record")
    return out


def document_record_fingerprint(fields):
    """A document record's fingerprint (spec 11.11): its form checked, then exactly
    record_fingerprint. Raises for fields not in the profile's form."""
    problems = document_problems(fields)
    if problems:
        raise ValueError("not a valid document record: " + "; ".join(problems))
    return record_fingerprint(fields)


# ---- laboratory results, version 2 (spec 11.12) -------------------------------------------

LAB_FORMAT = "veilcore/lab-result/v2"
LAB_FILE = "lab-result.json"
LAB_KINDS = ("numbers", "pathogen", "match", "lineage", "dna-mark", "viability", "retraction")
LAB_REASONS = ("re-test", "correction", "retraction")
LAB_CALL_SCHEMAS = {
    "pathogen": "veilcore/schema/pathogen/v1",
    "match": "veilcore/schema/genetic-match/v1",
    "lineage": "veilcore/schema/lineage-check/v1",
    "dna-mark": "veilcore/schema/dna-mark/v1",
    "viability": "veilcore/schema/viability/v1",
    "retraction": "veilcore/schema/lab-retraction/v1",
}


def _line(v, mx=200):
    return (
        isinstance(v, str) and v != "" and len(v) <= mx and _one_line_problem("x", v) is None and v == v.strip()
        and not any(unicodedata.category(c) == "Cf" for c in v)
    )


def _sequence_run(v):
    run = 0
    for c in v.upper():
        run = run + 1 if c in "ACGT" else 0
        if run >= 10:
            return True
    return False


def _count(v):
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 1_000_000_000


def _only(o, req, opt=()):
    return all(k in o for k in req) and all(k in req or k in opt for k in o)


def _ref(v):
    return isinstance(v, dict) and _only(v, ("id", "version")) and _line(v["id"]) and _line(v["version"])


def _ct(v):
    if not isinstance(v, str) or not v.isascii():
        return False
    w, _, f = v.partition(".")
    if "." in v and not (1 <= len(f) <= 2 and f.isdigit()):
        return False
    return w.isdigit() and len(w) <= 2 and (w == "0" or w[0] != "0")


def _decimal(v, positive):
    """A decimal as a report prints it: no sign, no exponent, 15 whole digits and 6 decimals at most."""
    if not isinstance(v, str) or not v.isascii():
        return False
    w, dot, f = v.partition(".")
    if dot and not (1 <= len(f) <= 6 and f.isdigit()):
        return False
    if not (w.isdigit() and 1 <= len(w) <= 15 and (w == "0" or w[0] != "0")):
        return False
    return not positive or not _zero(v)


def _zero(v):
    w, _, f = v.partition(".")
    return w == "0" and set(f) <= {"0"}


def _ambiguous(v):
    """A whole part that is not 0, a point, exactly three digits ("1.000", "12.500", "1234.567"): in German,
    French and Spanish the point is a thousands separator, so these can read a thousand times bigger there.
    "0.125" stands: a thousands group never starts with 0."""
    w, dot, f = v.partition(".")
    return bool(dot) and len(w) >= 1 and w[0] != "0" and len(f) == 3


def _amount(v, positive):
    return (
        isinstance(v, dict) and _only(v, ("value", "unit")) and _decimal(v["value"], positive)
        and not _ambiguous(v["value"]) and _line(v["unit"], 60)
    )


def _viability_ok(r, s):
    """A viability result (spec 11.12): a sample taken before or after a kill step."""
    if not _only(r, ("batch", "stage", "strain", "sampled", "target", "portion", "cultures", "lod", "detected", "controls"), ("killStep", "before", "count")):
        return False
    stage = r["stage"]
    if stage not in ("before", "after") or not _line(r["batch"]) or not _is_hex32(r["strain"]):
        return False
    if (stage == "after") != ("killStep" in r) or ("killStep" in r and not _line(r["killStep"])):
        return False
    if "before" in r and not (stage == "after" and _is_hex32(r["before"])):
        return False
    if not (_line(r["target"]) and _line(r["portion"]) and _calendar_date(r["sampled"])):
        return False
    if _calendar_date(s.get("tested")) and r["sampled"] > s["tested"]:
        return False
    if "received" in s and _calendar_date(s["received"]) and r["sampled"] > s["received"]:
        return False
    c = r["cultures"]
    if not (isinstance(c, list) and 1 <= len(c) <= 4 and all(isinstance(x, dict) and _only(x, ("medium", "time", "temperature")) and _line(x["medium"]) and _line(x["time"], 60) and _line(x["temperature"], 60) for x in c)):
        return False
    if len({canonicalise(x) for x in c}) != len(c):
        return False
    if not _amount(r["lod"], True) or not isinstance(r["detected"], bool):
        return False
    # None recovered is below the limit of detection, never a count of 0: the count is left out.
    # Some recovered: the count is optional (enrichment gives none), above 0 when given.
    if r["detected"] is False and "count" in r:
        return False
    if "count" in r and not _amount(r["count"], True):
        return False
    k = r["controls"]
    return (
        isinstance(k, dict) and _only(k, ("positive", "positiveGrew"), ("negativeGrew",)) and _line(k["positive"])
        and k["positiveGrew"] is True and ("negativeGrew" not in k or k["negativeGrew"] is False)
    )


def _is_salt(v):
    """A salt: 64 lowercase hex characters, not all one byte value (spec 11.12, bindingSalt)."""
    return _is_hex32(v) and len(set(v[i:i + 2] for i in range(0, 64, 2))) > 1


def lab_statement_problems(s):
    if not isinstance(s, dict):
        return ["a statement is an object"]
    out = []
    if s.get("format") != LAB_FORMAT:
        out.append("format")
    if not _only(s, ("format", "kind", "subject", "sampleId", "accession", "method", "tested"), ("panel", "received", "qc", "result", "replaces", "bindingSalt")):
        out.append("fields")
    if "bindingSalt" in s and not _is_salt(s["bindingSalt"]):
        out.append("bindingSalt")
    kind = s.get("kind")
    if kind not in LAB_KINDS:
        out.append("kind")
    subject = s.get("subject")
    if not _is_hex32(subject):
        out.append("subject")
    for k in ("sampleId", "accession"):
        if not _line(s.get(k)):
            out.append(k)
    if not _ref(s.get("method")):
        out.append("method")
    if "panel" in s and not _ref(s["panel"]):
        out.append("panel")
    if not _calendar_date(s.get("tested")):
        out.append("tested")
    if "received" in s and not (_calendar_date(s["received"]) and _calendar_date(s.get("tested")) and s["received"] <= s["tested"]):
        out.append("received")
    if "qc" in s:
        q = s["qc"]
        if not (isinstance(q, list) and 1 <= len(q) <= 12 and all(isinstance(x, dict) and _only(x, ("name", "value")) and _line(x["name"], 60) and _line(x["value"], 60) for x in q) and len({x["name"] for x in q}) == len(q)):
            out.append("qc")
    r = s.get("result")
    if kind == "retraction":
        if "result" in s:
            out.append("result")
    elif kind in LAB_KINDS:
        if not isinstance(r, dict):
            out.append("result")
        elif kind == "numbers":
            if not (_only(r, ("form",)) and _line(r["form"])):
                out.append("form")
        elif kind == "pathogen":
            if not (_only(r, ("target", "sampleType", "detected"), ("ct",)) and _line(r["target"]) and _line(r["sampleType"]) and isinstance(r["detected"], bool) and ("ct" not in r or _ct(r["ct"]))):
                out.append("pathogen")
        elif kind == "match":
            ok = _only(r, ("other", "matches"), ("otherSampleId", "compared", "differing")) and _is_hex32(r["other"]) and r["other"] != subject and isinstance(r["matches"], bool)
            ok = ok and ("otherSampleId" not in r or _line(r["otherSampleId"]))
            ok = ok and ("compared" not in r or (_count(r["compared"]) and r["compared"] >= 1)) and ("differing" not in r or _count(r["differing"]))
            if ok and "compared" in r and "differing" in r and r["differing"] > r["compared"]:
                ok = False
            if not ok:
                out.append("match")
        elif kind == "lineage":
            p = r.get("parents")
            ok = _only(r, ("parents", "consistent"), ("compared", "conflicts")) and isinstance(p, list) and 1 <= len(p) <= 2
            ok = ok and all(_is_hex32(x) and x != subject for x in p) and len(set(p)) == len(p) and isinstance(r["consistent"], bool)
            ok = ok and ("compared" not in r or (_count(r["compared"]) and r["compared"] >= 1))
            if ok and "conflicts" in r:
                c = r["conflicts"]
                ok = isinstance(c, list) and len(c) == len(p) and all(_count(x) for x in c)
                if ok and "compared" in r and any(x > r["compared"] for x in c):
                    ok = False
            if not ok:
                out.append("lineage")
        elif kind == "viability":
            if not _viability_ok(r, s):
                out.append("viability")
        elif kind == "dna-mark":
            if not (_only(r, ("seal", "found"), ("label",)) and _is_hex32(r["seal"]) and isinstance(r["found"], bool) and ("label" not in r or (_line(r["label"]) and not _sequence_run(r["label"])))):
                out.append("dna-mark")
    rep = s.get("replaces")
    if "replaces" in s and not (isinstance(rep, dict) and _only(rep, ("result", "reason")) and _is_hex32(rep["result"]) and rep["reason"] in LAB_REASONS):
        out.append("replaces")
    reason = rep.get("reason") if isinstance(rep, dict) else None
    if (kind == "retraction") != (reason == "retraction"):
        out.append("retraction")
    return out


def lab_statement_file(s):
    p = lab_statement_problems(s)
    if p:
        raise ValueError("not a valid statement: " + ", ".join(p))
    b = canonicalise(s).encode("utf-8")
    return {"name": LAB_FILE, "sha256": hashlib.sha256(b).hexdigest(), "size": len(b)}


def _schema_id(schema):
    mask, numeric = _schema_masks(schema)
    digest = hashlib.sha256(canonicalise(schema).encode("utf-8")).digest()
    return _h(_tag("veilcore:v1:fschema"), digest, _terms_bytes(mask, numeric, int(schema["k"]))).hex()


def _call_values(s):
    v = [None] * 16
    r = s.get("result") or {}
    b = lambda x: "1" if x else "0"
    n = lambda k: None if k not in r else str(r[k])
    kind = s["kind"]
    if kind == "pathogen":
        v[0] = b(r["detected"])
        if "ct" in r:
            w, _, f = r["ct"].partition(".")
            v[1] = str(int(w) * 100 + int((f + "00")[:2]))
    elif kind == "match":
        v[0], v[1], v[2] = b(r["matches"]), n("compared"), n("differing")
    elif kind == "lineage":
        c = r.get("conflicts")
        v[0], v[1] = b(r["consistent"]), n("compared")
        if c is not None:
            v[2] = str(c[0])
            if len(c) > 1:
                v[3] = str(c[1])
    elif kind == "dna-mark":
        v[0] = b(r["found"])
    elif kind == "viability":
        v[0], v[1] = b(r["detected"]), "1" if r["stage"] == "after" else "0"
    elif kind == "retraction":
        v[0] = "1"
    return v


def lab_binding(job):
    """True when a statement binds to a record (spec 11.12); raises when it doesn't."""
    f, s, values, schemas = job["fields"], job["statement"], job["values"], job["schemas"]
    want = lab_statement_file(s)
    p = document_problems(f)
    if p:
        raise ValueError("not a document record: " + "; ".join(p))
    if f["type"] != "lab-report":
        raise ValueError("not a lab report")
    entries = [x for x in f["files"] if x["name"] == LAB_FILE]
    if len(entries) != 1 or entries[0]["sha256"] != want["sha256"] or entries[0]["size"] != want["size"]:
        raise ValueError("the statement file is not this statement's")
    if f["issued"] != s["tested"]:
        raise ValueError("issued is not the date tested")
    if f["about"] != [{"name": s["sampleId"]}]:
        raise ValueError("about names the sample ID, and only it")
    if f["reference"] != s["accession"]:
        raise ValueError("reference is not the accession number")
    if f["issuer"] != f["holder"]:
        raise ValueError("issuer and holder are not the same laboratory name")
    if "fieldSchema" not in f:
        raise ValueError("no field set")
    form = s["result"]["form"] if s["kind"] == "numbers" else LAB_CALL_SCHEMAS[s["kind"]]
    if s["kind"] == "numbers" and form in LAB_CALL_SCHEMAS.values():
        raise ValueError("a numbers result under a call form")
    if form not in schemas or _schema_id(schemas[form]) != f["fieldSchema"]:
        raise ValueError("fieldSchema is not the id of the kind's form")
    if not isinstance(values, list) or len(values) != 16:
        raise ValueError("values are sixteen")
    if s["kind"] != "numbers" and _call_values(s) != values:
        raise ValueError("the field set does not agree with the statement")
    return True


def _replaces(later, later_code, earlier, earlier_code):
    """Whether later replaces (or withdraws) earlier under spec 11.12, "Replacing". Keys are the caller's."""
    rep = later.get("replaces")
    return (
        isinstance(rep, dict) and rep.get("result") == earlier_code and later_code != earlier_code
        and later["subject"] == earlier["subject"] and later["tested"] >= earlier["tested"]
        and (earlier.get("replaces") or {}).get("result") != later_code
    )


def lab_viability_pair(job):
    """True when an after-sample's viability result pairs with the before-sample it names (spec 11.12); raises when not."""
    a, b, code = job["after"], job["before"], job["beforeCode"]
    lab_statement_file(a)
    lab_statement_file(b)
    if a["kind"] != "viability" or b["kind"] != "viability":
        raise ValueError("both are viability results")
    ar, br = a["result"], b["result"]
    if ar["stage"] != "after" or br["stage"] != "before":
        raise ValueError("one is an after-sample and the other a before-sample")
    if ar.get("before") != code:
        raise ValueError("the after-sample does not name this result")
    if ar["batch"] != br["batch"] or ar["strain"] != br["strain"]:
        raise ValueError("another batch or strain record")
    if ar["target"] != br["target"]:
        raise ValueError("the two tests recover different things")
    if br["sampled"] > ar["sampled"]:
        raise ValueError("the before-sample was taken after the after-sample")
    # The two results are held too: one that replaces or withdraws the other breaks the pair.
    if _replaces(a, job.get("afterCode", ""), b, code):
        raise ValueError("the after-sample's result replaces the before-sample's")
    if "afterCode" in job and _replaces(b, code, a, job["afterCode"]):
        raise ValueError("the before-sample's result replaces the after-sample's")
    for h in job.get("held") or []:
        st = h["statement"]
        if lab_statement_problems(st):
            continue
        if _replaces(st, h["code"], b, code):
            raise ValueError("the before-sample's result was replaced or withdrawn")
        if "afterCode" in job and _replaces(st, h["code"], a, job["afterCode"]):
            raise ValueError("the after-sample's result was replaced or withdrawn")
    return True


def dna_mark_seal(sequence, salt):
    if not (isinstance(sequence, str) and 10 <= len(sequence) <= 100000 and all(c in "ACGT" for c in sequence)):
        raise ValueError("a mark is 10 to 100000 of A, C, G and T")
    if not _is_hex32(salt):
        raise ValueError("the salt is 64 lowercase hex characters")
    return hashlib.sha256(b"veilcore:dnamark:v1\x00" + bytes.fromhex(salt) + sequence.encode("ascii")).hexdigest()


def lab_name_binding(key, subject, salt):
    """SHA-256("veilcore:lab-result-binding:v2:salted" 0x00 || key || subject || salt), hex (spec 11.12)."""
    if not (isinstance(key, str) and len(key) == 128 and all(c in "0123456789abcdef" for c in key)):
        raise ValueError("the key is 128 lowercase hex characters, x then y")
    if not _is_hex32(subject):
        raise ValueError("the subject is 64 lowercase hex characters")
    if not _is_salt(salt):
        raise ValueError("the salt is 64 lowercase hex characters, not all one byte value")
    return hashlib.sha256(b"veilcore:lab-result-binding:v2:salted\x00" + bytes.fromhex(key) + bytes.fromhex(subject) + bytes.fromhex(salt)).hexdigest()


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
    elif op == "keyFromSecret":
        s = job["input"]["recordSecret"]
        identity, salt = identity_from_secret(s), key_salt_of(s)
        print(json.dumps({"result": {"identity": identity, "keySalt": salt, "keyBinding": key_binding_of(identity, salt)}}))
    elif op == "recordFingerprint":
        print(json.dumps({"result": record_fingerprint(job["input"])}))
    elif op == "animalFingerprint":
        print(json.dumps({"result": animal_record_fingerprint(job["input"])}))
    elif op == "strainFingerprint":
        print(json.dumps({"result": strain_record_fingerprint(job["input"])}))
    elif op == "documentFingerprint":
        print(json.dumps({"result": document_record_fingerprint(job["input"])}))
    elif op == "labStatement":
        print(json.dumps({"result": lab_statement_file(job["input"])}))
    elif op == "labBinding":
        print(json.dumps({"result": lab_binding(job["input"])}))
    elif op == "dnaMarkSeal":
        i = job["input"]
        print(json.dumps({"result": dna_mark_seal(i["sequence"], i["salt"])}))
    elif op == "labViabilityPair":
        print(json.dumps({"result": lab_viability_pair(job["input"])}))
    elif op == "labNameBinding":
        i = job["input"]
        print(json.dumps({"result": lab_name_binding(i["key"], i["subject"], i["salt"])}))
    elif op == "keyMatch":
        i = job["input"]
        print(json.dumps({"result": key_matches_record(i.get("identity"), i.get("fingerprint"), i.get("keySalt"), i.get("contentHash"))}))
    else:
        print(json.dumps({"error": f"unknown op {op}"}))
        sys.exit(1)

if __name__ == "__main__":
    main()
