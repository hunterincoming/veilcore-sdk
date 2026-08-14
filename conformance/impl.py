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
        if isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                raise ValueError("non-finite numbers cannot be committed")
            # RFC 8785 3.2.2.3: ECMAScript shortest round-trip. Python pads exponents
            # to two digits and ECMAScript does not, so 1e-07 becomes 1e-7.
            out = repr(value)
            if "e" in out:
                mantissa, exponent = out.split("e")
                sign = "-" if exponent.startswith("-") else ""
                digits = exponent.lstrip("+-").lstrip("0") or "0"
                out = f"{mantissa}e{sign}{digits}"
            return out
        return str(value)

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


def main():
    job = json.loads(sys.stdin.read())
    op = job["op"]
    if op == "canonicalise":
        print(json.dumps({"result": canonicalise(job["input"])}))
    elif op == "commit":
        print(json.dumps({"result": compute_commitment(job["input"])}))
    else:
        print(json.dumps({"error": f"unknown op {op}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
