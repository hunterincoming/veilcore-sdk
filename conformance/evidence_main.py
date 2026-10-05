

# ─────────────────────────────────────────────────────────────── evidence package
#
# Everything above is the reference Python implementation of the VeilCore record format,
# unchanged. Below: the checks for an evidence package. Standard library only; run
#
#     python3 verify.py
#
# in the folder the package was unpacked into. It checks what can be checked offline
# and lists what needs a lookup (SPEC section 9).
#
# MANIFEST.json catches accidental damage only. It sits beside the files, so anyone who
# edits a file can rewrite it to match. What deliberate editing cannot get past is the
# commitment recomputed from record.json (step 2) and that commitment's anchor.
#
# A malformed package is reported as a failed check, never as a Python traceback.

_OTS_HEADER = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
_MAX_FILE = 64 * 1024 * 1024


def _plain_name(name):
    """A manifest names files in this folder by plain name: no path, nothing hidden."""
    import re
    return isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", name) is not None


def _der_header(b, pos, limit):
    """(tag, start of contents, end) of the DER element at pos, or raise ValueError."""
    if pos + 2 > limit:
        raise ValueError("data ends inside a header")
    tag = b[pos]
    first = b[pos + 1]
    p = pos + 2
    if first < 0x80:
        n = first
    else:
        k = first & 0x7F
        if k == 0 or k > 4 or p + k > limit or b[p] == 0:
            raise ValueError("bad length")
        n = int.from_bytes(b[p:p + k], "big")
        if n < 0x80:
            raise ValueError("length not minimal")
        p += k
    if n > limit - p:
        raise ValueError("length runs past its container")
    return tag, p, p + n


def _timestamp_token(stated):
    """The DER TimeStampToken inside what a record states: the token itself, or the token
    element of a full TimeStampResp. The same rule the TypeScript reader applies, so a .tst
    file must equal it exactly rather than merely appear somewhere inside it."""
    tag, body, end = _der_header(stated, 0, len(stated))
    if tag != 0x30 or end != len(stated):
        raise ValueError("not one DER SEQUENCE")
    t1, b1, e1 = _der_header(stated, body, end)
    if t1 == 0x06:
        return stated  # already a ContentInfo
    if t1 != 0x30 or e1 == end:
        raise ValueError("not a TimeStampResp with a token")
    t2, _, e2 = _der_header(stated, e1, end)
    if t2 != 0x30 or e2 != end:
        raise ValueError("unexpected fields in the TimeStampResp")
    return stated[e1:e2]


def _b64(text):
    """Strict base64, as the TypeScript reader takes it: whitespace ignored, padding optional."""
    import base64
    import binascii
    if not isinstance(text, str):
        raise ValueError("not base64")
    packed = "".join(text.split())
    clean = packed.rstrip("=")
    if len(packed) - len(clean) > 2 or (clean != packed and len(packed) % 4) or len(clean) % 4 == 1:
        raise ValueError("not base64")
    try:
        out = base64.b64decode(clean + "=" * (-len(clean) % 4), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("not base64")
    if base64.b64encode(out).decode("ascii").rstrip("=") != clean:
        raise ValueError("not canonical base64")
    return out


def _evidence_main():
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    path = lambda n: os.path.join(here, n)
    state = {"ok": True}

    def say(mark, text):
        print(f"  [{mark}] {text}" if mark else f"        {text}")

    def fail(text):
        say("FAIL", text)
        state["ok"] = False

    def read(name):
        """Bytes of a file in this folder, or None if it is not there or not a plain file."""
        p = path(name)
        if not os.path.isfile(p) or os.path.getsize(p) > _MAX_FILE:
            return None
        with open(p, "rb") as f:
            return f.read()

    def read_json(name):
        raw = read(name)
        if raw is None:
            return None, f"{name} is missing"
        try:
            return json.loads(raw.decode("utf-8")), None
        except (UnicodeDecodeError, ValueError) as e:
            return None, f"{name} is not valid JSON: {e}"

    print("VeilCore evidence package check\n")

    # 1. Every file is the one the package was built with (accidental damage; see above).
    print("1. Files")
    manifest, why = read_json("MANIFEST.json")
    listed = {}
    if manifest is None:
        fail(why)
    elif not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict) or manifest.get("format") != "veilcore-evidence/v1":
        fail("MANIFEST.json is not a veilcore-evidence/v1 manifest")
    else:
        listed = manifest["files"]
        for name, digest in sorted(listed.items()):
            if not _plain_name(name) or name == "MANIFEST.json":
                fail(f"MANIFEST.json lists {name[:100]!r}, which is not a plain file name"); continue
            if not _is_hex32(digest):
                fail(f"MANIFEST.json gives no SHA-256 for {name}"); continue
            data = read(name)
            if data is None:
                fail(f"{name} is missing")
            elif hashlib.sha256(data).hexdigest() == digest:
                say("ok", f"{name}")
            else:
                fail(f"{name} has changed since the package was built")
        for required in ("record.json", "verify.py"):
            if required not in listed:
                fail(f"MANIFEST.json does not list {required}")
        for entry in sorted(os.listdir(here)):
            # Hidden files (.DS_Store) and folders (__MACOSX, __pycache__) come from unzipping
            # and running; they are not part of the package and are not read.
            if entry.startswith(".") or entry.startswith("__") or not os.path.isfile(path(entry)):
                continue
            if entry != "MANIFEST.json" and entry not in listed:
                fail(f"{entry} is not in MANIFEST.json: it was added after the package was built")
        say("", "(the manifest catches accidental damage only: whoever edits a file can rewrite it.")
        say("", " Step 2 is what deliberate editing cannot get past.)")

    # 2. The record is unaltered: recompute its commitment.
    print("\n2. The record")
    record, why = read_json("record.json")
    computed = None
    if record is None:
        fail(why)
        record = {}
    elif not isinstance(record, dict):
        fail("record.json is not a JSON object")
        record = {}
    else:
        try:
            computed = compute_commitment(record)
        except Exception as e:  # any refusal by the reference implementation
            fail(f"the commitment cannot be computed: {e}")
        if computed is not None:
            if computed == record.get("commitment"):
                say("ok", f"commitment recomputed: {computed}")
                say("ok", "the record is exactly as it was when sealed")
            else:
                fail(f"recomputed {computed}, but the record states {str(record.get('commitment'))[:80]}")
    if computed is not None and isinstance(manifest, dict) and "commitment" in manifest and manifest["commitment"] != computed:
        fail("MANIFEST.json names a different commitment")
    commitment_bin = read("commitment.bin")
    if commitment_bin is not None and computed is not None and commitment_bin.hex() != computed:
        fail("commitment.bin is not the record's commitment")

    # 3. The record is in the anchored batch: fold the inclusion proof.
    print("\n3. The batch")
    root = None
    proof = {}
    if os.path.exists(path("inclusion-proof.json")):
        loaded, why = read_json("inclusion-proof.json")
        if loaded is None or not isinstance(loaded, dict):
            fail(why or "inclusion-proof.json is not a JSON object")
        else:
            proof = loaded
            if proof.get("commitment") != computed:
                fail("the inclusion proof is for a different commitment")
            else:
                try:
                    folded = fold_proof(proof["commitment"], proof.get("path"))
                except ValueError as e:
                    folded = None
                    fail(f"the inclusion proof is malformed: {e}")
                if folded is not None:
                    if folded == proof.get("root"):
                        root = folded
                        say("ok", f"the commitment is in batch {str(proof.get('batchId'))[:100]} with root {root}")
                    else:
                        fail("the inclusion proof does not fold to its stated root")
    else:
        say("--", "no inclusion proof in this package: the record is not shown to be in an anchored batch")

    # 4. The Bitcoin timestamp file names the batch root.
    print("\n4. Timestamps")
    root_bin = read("root.bin")
    if root_bin is not None and root_bin.hex() != root:
        fail("root.bin is not the batch root of this record's inclusion proof")
    if os.path.exists(path("root.bin.ots")):
        ots = read("root.bin.ots")
        if ots is None or root_bin is None:
            fail("root.bin.ots needs root.bin beside it")
        elif root is None:
            fail("root.bin.ots dates a batch root this package does not tie to the record")
        elif not ots.startswith(_OTS_HEADER) or len(ots) < len(_OTS_HEADER) + 34 or ots[len(_OTS_HEADER)] != 0x01:
            fail("root.bin.ots is not an OpenTimestamps (version 1) file")
        elif ots[len(_OTS_HEADER) + 1] != 0x08 or ots[len(_OTS_HEADER) + 2:len(_OTS_HEADER) + 34] != hashlib.sha256(root_bin).digest():
            fail("root.bin.ots is for a different file")
        else:
            say("ok", "root.bin.ots is an OpenTimestamps proof for root.bin")
            say("to do", "confirm it against Bitcoin: `ots upgrade root.bin.ots` then `ots verify root.bin.ots`")
            say("", "(the OpenTimestamps client: https://github.com/opentimestamps/opentimestamps-client)")
    else:
        say("--", "no OpenTimestamps file in this package")
    anchors = record.get("anchor")
    anchors = anchors if isinstance(anchors, list) else ([anchors] if anchors else [])
    # (anchor, where it is carried). Token files are named as the SDK writes them: a
    # record's rfc3161 anchors with a token, in order, are rfc3161-record-1.tst, -2, ...;
    # one on the inclusion proof is rfc3161-batch.tst. SPEC 3.2: a record token stamps the
    # commitment's 32 raw bytes (commitment.bin), a batch token the root's (root.bin).
    carried = [(a, "record") for a in anchors]
    if isinstance(proof.get("anchor"), dict):
        carried.append((proof["anchor"], "batch"))
    record_tokens = 0
    for a, where in carried:
        if not isinstance(a, dict):
            continue
        kind = a.get("kind", "ledger")
        if kind == "ledger" and a.get("txHash"):
            say("to do", f"confirm transaction {str(a.get('txHash'))[:200]} on {str(a.get('chain'))[:60]} ({str(a.get('network'))[:60]}) published the batch root {root or ''}".rstrip())
        elif kind == "ledger":
            say("--", f"ledger anchor on {str(a.get('chain'))[:60]} ({str(a.get('network'))[:60]}) with no transaction: nothing to confirm yet")
        elif kind == "rfc3161" and not a.get("token"):
            say("--", "RFC 3161 anchor with no token: nothing to check")
        elif kind == "rfc3161":
            if where == "record":
                record_tokens += 1
                tst, data, stamped = f"rfc3161-record-{record_tokens}.tst", "commitment.bin", computed
            else:
                tst, data, stamped = "rfc3161-batch.tst", "root.bin", root
            tst_bytes, data_bytes = read(tst), read(data)
            if tst_bytes is None or data_bytes is None:
                say("to do", "the RFC 3161 token is in the record (base64) but not saved in this package; save it as a .tst file and verify it with `openssl ts -verify`")
                continue
            try:
                stated = _timestamp_token(_b64(a["token"]))
            except ValueError:
                stated = None
            if stamped is None or data_bytes.hex() != stamped:
                fail(f"{data} is not the {'commitment' if where == 'record' else 'batch root'} the token should stamp")
            elif stated is None or tst_bytes != stated:
                fail(f"{tst} is not the token the {'record' if where == 'record' else 'inclusion proof'} states")
            else:
                say("ok", f"{tst} is the RFC 3161 token the {'record' if where == 'record' else 'inclusion proof'} states, over {data}")
                say("to do", "verify its signature and imprint (Python's standard library cannot). Run:")
                say("", f"openssl ts -verify -data {data} -in {tst} -token_in -CAfile TSA-ROOT.pem")
                say("", "where TSA-ROOT.pem is the root certificate of the TSA" + (f" ({str(a.get('tsa'))[:100]})" if a.get("tsa") else "") + ", obtained from the TSA itself;")
                say("", "add -untrusted INTERMEDIATES.pem if the token does not carry them. 'Verification: OK' means")
                say("", "the imprint, signature, time-stamping key usage and chain to that root all hold (revocation is not checked).")
                qualified = a.get("qualified")
                if isinstance(qualified, dict) and qualified.get("scheme"):
                    say("to do", f"confirm the TSA's qualified status ({str(qualified['scheme'])[:100]}) on the EU trusted list; openssl does not check it")
        elif kind == "notarial":
            say("to do", "confirm the notarial reference with the notary")

    # 5. Claims, if any, need a ledger lookup.
    if os.path.exists(path("claims.json")):
        print("\n5. Claims")
        say("to do", "each claim in claims.json is checked on the ledger and against SPEC 4.5's checklist")

    print("\nNot established by any of this: that the record is true, that material is the subject")
    print("described, or that anything still exists (SPEC 9.3).")
    print("\nRESULT: " + ("every offline check passed" if state["ok"] else "SOME CHECKS FAILED"))
    sys.exit(0 if state["ok"] else 1)


if __name__ == "__main__":
    try:
        _evidence_main()
    except SystemExit:
        raise
    except Exception as e:  # never a traceback in front of a court: say what failed
        print(f"\n  [FAIL] the package could not be checked: {type(e).__name__}: {e}")
        print("\nRESULT: SOME CHECKS FAILED")
        sys.exit(1)
