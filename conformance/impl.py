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
    Canonical serialisation per the VeilCore spec.

    Object keys sorted by Unicode code point. Absent optionals omitted, never null.
    UTF-8, NFC normalised. No insignificant whitespace. Array order preserved, because
    parent order is meaningful in some domains.
    """
    if value is None:
        return "null"
    if isinstance(value, str):
        # ensure_ascii=False keeps the character; JSON escaping rules still apply.
        return json.dumps(unicodedata.normalize("NFC", value), ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        # Match JSON number formatting: integers without a trailing .0
        if isinstance(value, float) and value.is_integer():
            return str(int(value))
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalise(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(k for k in value if value[k] is not None or k in value)
        # An explicit null is preserved; an absent key is simply not present.
        parts = [
            json.dumps(k, ensure_ascii=False, separators=(",", ":")) + ":" + canonicalise(value[k])
            for k in keys
        ]
        return "{" + ",".join(parts) + "}"
    raise ValueError(f"cannot canonicalise {type(value)}")


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
    for key in ("extensions", "jurisdictionBindings", "supersedes"):
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
