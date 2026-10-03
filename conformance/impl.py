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
        "extensions", "jurisdictionBindings", "supersedes",
        # What every subject has, whatever domain it comes from.
        "subject", "identification", "registrations",
    ):
        if env.get(key) is not None:
            fields[key] = env[key]
    return fields


def compute_commitment(env):
    return hashlib.sha256(canonicalise(committed_fields(env)).encode("utf-8")).hexdigest()


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
    elif op == "fold":
        print(json.dumps({"result": fold_proof(job["input"]["commitment"], job["input"]["path"])}))
    else:
        print(json.dumps({"error": f"unknown op {op}"}))
        sys.exit(1)

if __name__ == "__main__":
    main()
