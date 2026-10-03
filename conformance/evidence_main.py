

# ─────────────────────────────────────────────────────────────── evidence package
#
# Everything above is the reference Python implementation of the VeilCore record format,
# unchanged. Below: the checks for an evidence package. Standard library only; run
#
#     python3 verify.py
#
# in the folder the package was unpacked into. It checks what can be checked offline
# and lists what needs a lookup (SPEC section 9).

def _evidence_main():
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    path = lambda n: os.path.join(here, n)
    ok = True

    def say(mark, text):
        print(f"  [{mark}] {text}")

    print("VeilCore evidence package check\n")

    # 1. Every file is the one the package was built with.
    with open(path("MANIFEST.json"), "rb") as f:
        manifest = json.loads(f.read().decode("utf-8"))
    print("1. Files")
    for name, digest in sorted(manifest["files"].items()):
        try:
            with open(path(name), "rb") as f:
                actual = hashlib.sha256(f.read()).hexdigest()
        except FileNotFoundError:
            say("FAIL", f"{name} is missing"); ok = False; continue
        if actual == digest:
            say("ok", f"{name}")
        else:
            say("FAIL", f"{name} has changed since the package was built"); ok = False

    # 2. The record is unaltered: recompute its commitment.
    print("\n2. The record")
    with open(path("record.json"), "rb") as f:
        record = json.loads(f.read().decode("utf-8"))
    try:
        computed = compute_commitment(record)
    except Exception as e:
        say("FAIL", f"the commitment cannot be computed: {e}"); computed = None; ok = False
    if computed is not None:
        if computed == record.get("commitment"):
            say("ok", f"commitment recomputed: {computed}")
            say("ok", "the record is exactly as it was when sealed")
        else:
            say("FAIL", f"recomputed {computed}, but the record states {record.get('commitment')}"); ok = False

    # 3. The record is in the anchored batch: fold the inclusion proof.
    print("\n3. The batch")
    root = None
    proof = {}
    if os.path.exists(path("inclusion-proof.json")):
        with open(path("inclusion-proof.json"), "rb") as f:
            proof = json.loads(f.read().decode("utf-8"))
        if proof.get("commitment") != computed:
            say("FAIL", "the inclusion proof is for a different commitment"); ok = False
        else:
            root = fold_proof(proof["commitment"], proof["path"])
            if root == proof.get("root"):
                say("ok", f"the commitment is in batch {proof.get('batchId')} with root {root}")
            else:
                say("FAIL", "the inclusion proof does not fold to its stated root"); ok = False
    else:
        say("--", "no inclusion proof in this package: the record is not shown to be in an anchored batch")

    # 4. The Bitcoin timestamp file names the batch root.
    print("\n4. Timestamps")
    if os.path.exists(path("root.bin")) and os.path.exists(path("root.bin.ots")):
        with open(path("root.bin"), "rb") as f:
            root_bin = f.read()
        with open(path("root.bin.ots"), "rb") as f:
            ots = f.read()
        header = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
        if root is not None and root_bin.hex() != root:
            say("FAIL", "root.bin is not the batch root"); ok = False
        elif not ots.startswith(header) or len(ots) < len(header) + 34:
            say("FAIL", "root.bin.ots is not an OpenTimestamps file"); ok = False
        elif ots[len(header) + 1] != 0x08 or ots[len(header) + 2:len(header) + 34] != hashlib.sha256(root_bin).digest():
            say("FAIL", "root.bin.ots is for a different file"); ok = False
        else:
            say("ok", "root.bin.ots is an OpenTimestamps proof for root.bin")
            say("to do", "confirm it against Bitcoin: `ots upgrade root.bin.ots` then `ots verify root.bin.ots`")
            say("", "(the OpenTimestamps client: https://github.com/opentimestamps/opentimestamps-client)")
    else:
        say("--", "no OpenTimestamps file in this package")
    anchors = record.get("anchor")
    anchors = anchors if isinstance(anchors, list) else ([anchors] if anchors else [])
    if proof.get("anchor"):
        anchors.append(proof["anchor"])
    for a in anchors:
        if not isinstance(a, dict):
            continue
        kind = a.get("kind", "ledger")
        if kind == "ledger" and a.get("txHash"):
            say("to do", f"confirm transaction {a.get('txHash')} on {a.get('chain')} ({a.get('network')}) published the batch root {root or ''}".rstrip())
        elif kind == "ledger":
            say("--", f"ledger anchor on {a.get('chain')} ({a.get('network')}) with no transaction: nothing to confirm yet")
        elif kind == "rfc3161":
            say("to do", "verify the RFC 3161 token's signature and imprint with the TSA's certificate")
        elif kind == "notarial":
            say("to do", "confirm the notarial reference with the notary")

    # 5. Claims, if any, need a ledger lookup.
    if os.path.exists(path("claims.json")):
        print("\n5. Claims")
        say("to do", "each claim in claims.json is checked on the ledger and against SPEC 4.5's checklist")

    print("\nNot established by any of this: that the record is true, that material is the subject")
    print("described, or that anything still exists (SPEC 9.3).")
    print("\nRESULT: " + ("every offline check passed" if ok else "SOME CHECKS FAILED"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    _evidence_main()
