#!/usr/bin/env python3
"""Acceptance verifier for the ``verify`` compose service.

Runs entirely over HTTP against a running seal server:

  0. waits for /healthz, builds + API smoke (group create, get)
  1. threshold shortfall is rejected (422) and leaves history AND the
     Merkle root untouched
  2. valid first package: digest/seq/unique head are exactly as expected,
     and the confirm response carries the log size + cumulative root
  3. idempotent retransmission replays the same receipt, creates no
     history and does not move the log
  4. same op_id with a changed payload conflicts (409), log unmoved
  5. concurrent submissions racing for the same predecessor: exactly one
     wins, the log advances exactly once
  6. Merkle consistency proofs: an independent RFC 6962 verifier (inline
     below, hashlib only) confirms the old root is a prefix of the new
     one, that tampered proofs FAIL verification, and that degenerate or
     out-of-range requests get deterministic results

Exits 0 only if every check passes.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

# Allow `python scripts/verify.py` from any CWD (image WORKDIR is the project root).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

HOST = os.environ.get("SEAL_TARGET_HOST", "seal")
PORT = int(os.environ.get("SEAL_TARGET_PORT", "8080"))
BASE = f"http://{HOST}:{PORT}"

_failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" -- {detail}" if detail else ""), flush=True)
    if not ok:
        _failures.append(name)
    return ok


def call(method: str, path: str, body=None, raw: bytes | None = None):
    if raw is None and body is not None:
        raw = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        BASE + path, data=raw, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_healthy(timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, payload = call("GET", "/healthz")
            if status == 200 and payload.get("status") == "ok":
                return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    return False


def make_keys(n: int):
    out = []
    for _ in range(n):
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        out.append((priv, crypto.key_fingerprint(pub), crypto.public_key_hex(pub)))
    return out


def sig(priv, gid, prev, seq, config) -> str:
    msg = crypto.canonical_message(gid, prev, seq, config)
    return priv.sign(msg, ec.ECDSA(hashes.SHA256())).hex()


# --------------------------------------------------------------------------
# Independent RFC 6962 Merkle verifier — hashlib only, deliberately NOT
# importing app.merkle: this is the downstream party that knows only an
# old (size, root) pair, the new root and the proof, never the configs.
# --------------------------------------------------------------------------

LOG_LEAF_DOMAIN = b"LXe-ConfigSeal-Log/v1"
EMPTY_ROOT = hashlib.sha256(b"").digest()


def m_leaf(gid: str, seq: int, digest_hex: str) -> bytes:
    g = gid.encode("utf-8")
    data = (LOG_LEAF_DOMAIN + b"\x00" + len(g).to_bytes(2, "big") + g
            + seq.to_bytes(8, "big") + bytes.fromhex(digest_hex))
    return hashlib.sha256(b"\x00" + data).digest()


def m_root(leaf_hashes: list[bytes]) -> bytes:
    n = len(leaf_hashes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaf_hashes[0]
    k = 1 << (n.bit_length() - 1)
    if k == n:
        k >>= 1
    return hashlib.sha256(b"\x01" + m_root(leaf_hashes[:k])
                          + m_root(leaf_hashes[k:])).digest()


def m_verify(m: int, n: int, first_root: bytes, second_root: bytes,
             proof: list[bytes]) -> bool:
    """RFC 9162 §2.1.4.2: is root(m) a prefix commitment of root(n)?"""
    if m < 0 or m > n:
        return False
    if m == 0:
        return proof == [] and first_root == EMPTY_ROOT
    if m == n:
        return proof == [] and first_root == second_root
    path = [first_root, *proof] if m & (m - 1) == 0 else list(proof)
    if not path:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = hashlib.sha256(b"\x01" + c + fr).digest()
            sr = hashlib.sha256(b"\x01" + c + sr).digest()
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = hashlib.sha256(b"\x01" + sr + c).digest()
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


def unhex_proof(resp: dict) -> tuple[bytes, bytes, list[bytes]]:
    return (bytes.fromhex(resp["first_root"]), bytes.fromhex(resp["second_root"]),
            [bytes.fromhex(x) for x in resp["proof"]])


def package_body(keys, gid, op_id, prev, seq, config, idxs):
    return {
        "op_id": op_id, "prev_digest": prev, "seq": seq, "config": config,
        "signatures": [
            {"key_id": keys[i][1], "signature": sig(keys[i][0], gid, prev, seq, config)}
            for i in idxs
        ],
    }


def main() -> int:
    print(f"== lxe config-seal verifier -> {BASE} ==", flush=True)

    if not check("server health check /healthz", wait_healthy()):
        return 1

    gid = f"verify-{int(time.time())}"
    keys = make_keys(4)

    # -- build/API smoke: register a 2-of-4 group ---------------------------
    status, group = call("POST", "/v1/groups", {
        "group_id": gid, "threshold": 2, "public_keys": [k[2] for k in keys],
    })
    check("create seal group (2-of-4)", status == 201, f"status={status} body={group}")
    check("new group starts with an empty log",
          group.get("log") == {"size": 0, "root": EMPTY_ROOT.hex()},
          f"log={group.get('log')}")
    status, info = call("GET", f"/v1/groups/{gid}")
    check("read group, genesis head", status == 200
          and info["head"] == {"seq": 0, "digest": crypto.GENESIS_DIGEST},
          f"status={status} head={info.get('head')}")

    # -- 1. threshold shortfall rejected, history unchanged -----------------
    thin = package_body(keys, gid, "op-thin", crypto.GENESIS_DIGEST, 1, "cfg-0", (0,))
    status, err = call("POST", f"/v1/groups/{gid}/packages", thin)
    check("threshold shortfall rejected", status == 422
          and err.get("error") == "insufficient_threshold",
          f"status={status} err={err}")

    # tampered signature also rejected (extra coverage)
    bad = package_body(keys, gid, "op-bad", crypto.GENESIS_DIGEST, 1, "cfg-0", (0, 1))
    bad["signatures"][1]["signature"] = bad["signatures"][1]["signature"][:-2] + "00"
    status, err = call("POST", f"/v1/groups/{gid}/packages", bad)
    check("tampered signature rejected", status == 422
          and err.get("error") == "invalid_signature", f"status={status} err={err}")

    status, info = call("GET", f"/v1/groups/{gid}")
    check("rejections left the Merkle log empty",
          info.get("log") == {"size": 0, "root": EMPTY_ROOT.hex()},
          f"log={info.get('log')}")

    # -- 2. valid first package ---------------------------------------------
    p1_body = package_body(keys, gid, "op-1", crypto.GENESIS_DIGEST, 1, "field=1500V", (0, 1))
    status, p1 = call("POST", f"/v1/groups/{gid}/packages", p1_body)
    expected1 = crypto.package_digest(gid, crypto.GENESIS_DIGEST, 1, "field=1500V")
    check("valid first package confirmed", status == 201 and p1["seq"] == 1
          and p1["digest"] == expected1, f"status={status} p1={p1}")
    # the confirm response carries the log state; the root recomputes from
    # the leaf alone (independent of the server's own merkle module)
    root1 = m_root([m_leaf(gid, 1, expected1)]).hex()
    check("confirm response carries log size + cumulative root",
          p1.get("log") == {"size": 1, "root": root1}, f"log={p1.get('log')}")
    status, info = call("GET", f"/v1/groups/{gid}")
    check("unique chain head == package 1",
          info["head"] == {"seq": 1, "digest": expected1}, f"head={info.get('head')}")
    check("group read carries the same log state",
          info.get("log") == {"size": 1, "root": root1}, f"log={info.get('log')}")

    # -- 3. idempotent retransmission ---------------------------------------
    raw = json.dumps(p1_body).encode("utf-8")
    status, replay = call("POST", f"/v1/groups/{gid}/packages", raw=raw)
    check("idempotent retransmission replays receipt",
          status == 200 and replay.get("replay") is True
          and replay["digest"] == expected1 and replay["seq"] == 1,
          f"status={status} replay={replay}")
    check("replay carries the original log state",
          replay.get("log") == {"size": 1, "root": root1},
          f"log={replay.get('log')}")
    status, listing = call("GET", f"/v1/groups/{gid}/packages")
    check("retry wrote no extra history",
          len(listing["packages"]) == 1, f"n={len(listing['packages'])}")
    check("retry did not move the log",
          listing.get("log") == {"size": 1, "root": root1},
          f"log={listing.get('log')}")

    # -- 4. op_id reused with a different payload conflicts -----------------
    # Properly signed, well-formed, but the op_id is already confirmed for a
    # different payload -> hard 409, no new history.
    conflict = package_body(keys, gid, "op-1", crypto.GENESIS_DIGEST, 1, "field=9999V", (0, 1))
    status, err = call("POST", f"/v1/groups/{gid}/packages", conflict)
    check("same op_id different payload conflicts",
          status == 409 and err.get("error") == "op_id_conflict",
          f"status={status} err={err}")
    status, info = call("GET", f"/v1/groups/{gid}")
    check("conflict did not move the log",
          info.get("log") == {"size": 1, "root": root1},
          f"log={info.get('log')}")

    # -- 5. concurrent race for the same predecessor ------------------------
    race_results: list[tuple[int, dict]] = []
    lock = threading.Lock()

    def racer(i: int) -> None:
        body = package_body(keys, gid, f"op-race-{i}", expected1, 2, f"fork-{i}", (0, 1))
        st, payload = call("POST", f"/v1/groups/{gid}/packages", body)
        with lock:
            race_results.append((st, payload))

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [p for st, p in race_results if st == 201]
    losers = [(st, p) for st, p in race_results if st != 201]
    ok_race = (
        len(winners) == 1
        and all(st == 409 and p.get("error") == "stale_predecessor" for st, p in losers)
    )
    check("concurrent fork: exactly one winner, others stale",
          ok_race, f"winners={len(winners)} losers={[(st, p.get('error')) for st, p in losers]}")

    status, info = call("GET", f"/v1/groups/{gid}")
    winner_digest = winners[0]["digest"] if winners else None
    check("unique chain head after race",
          status == 200 and info["head"] == {"seq": 2, "digest": winner_digest},
          f"head={info.get('head')}")
    status, listing = call("GET", f"/v1/groups/{gid}/packages")
    check("history holds exactly two linear packages",
          [p["seq"] for p in listing["packages"]] == [1, 2]
          and listing["packages"][1]["prev_digest"] == expected1
          and listing["packages"][1]["digest"] == winner_digest,
          f"seqs={[p['seq'] for p in listing['packages']]}")

    # the log advanced exactly once, to the winner's leaf; the cumulative
    # root recomputes independently from the two confirmed packages
    root2 = m_root([m_leaf(gid, p["seq"], p["digest"])
                    for p in listing["packages"]]).hex()
    check("log advanced exactly once, root recomputes from packages",
          info.get("log") == {"size": 2, "root": root2}
          and listing.get("log") == info.get("log")
          and (winners[0].get("log") == info.get("log") if winners else False),
          f"log={info.get('log')} expected_root={root2}")

    # -- 6. Merkle consistency proofs ---------------------------------------
    # Downstream recorded (size=1, root1) when package 1 was confirmed; now
    # it fetches a proof and checks — with ONLY the two sizes, the two
    # roots and the sibling digests — that the current history extends it.
    status, pr = call("GET", f"/v1/groups/{gid}/log/consistency?first=1&second=2")
    fr, sr, proof = unhex_proof(pr) if status == 200 else (b"", b"", [])
    check("consistency proof 1->2 returns both recorded roots",
          status == 200 and pr["first_root"] == root1
          and pr["second_root"] == root2 and len(pr["proof"]) == 1,
          f"status={status} pr={pr}")
    check("independent verifier accepts the proof",
          status == 200 and m_verify(1, 2, fr, sr, proof))

    # tampered proofs MUST fail independent verification
    if status == 200 and proof:
        flipped = bytes([proof[0][0] ^ 1]) + proof[0][1:]
        check("tampered sibling digest fails verification",
              not m_verify(1, 2, fr, sr, [flipped]))
        check("swapped roots fail verification",
              not m_verify(1, 2, sr, fr, proof))
        check("truncated proof fails verification",
              not m_verify(1, 2, fr, sr, []))
    else:
        check("tampered sibling digest fails verification", False, "no proof fetched")
        check("swapped roots fail verification", False, "no proof fetched")
        check("truncated proof fails verification", False, "no proof fetched")

    # empty prefix: the empty tree is a prefix of every history
    status, pr = call("GET", f"/v1/groups/{gid}/log/consistency?first=0&second=2")
    fr0, sr0, proof0 = unhex_proof(pr) if status == 200 else (b"", b"", [b""])
    check("empty prefix: empty proof, empty-tree root",
          status == 200 and pr["proof"] == []
          and pr["first_root"] == EMPTY_ROOT.hex()
          and pr["second_root"] == root2
          and m_verify(0, 2, fr0, sr0, proof0),
          f"status={status} pr={pr}")

    # equal sizes: empty proof, identical roots
    status, pr = call("GET", f"/v1/groups/{gid}/log/consistency?first=2&second=2")
    check("equal sizes: empty proof, identical roots",
          status == 200 and pr["proof"] == []
          and pr["first_root"] == pr["second_root"] == root2,
          f"status={status} pr={pr}")

    # deterministic rejections
    status, err = call("GET", f"/v1/groups/{gid}/log/consistency?first=2&second=1")
    check("first > second rejected", status == 400
          and err.get("error") == "bad_range", f"status={status} err={err}")
    status, err = call("GET", f"/v1/groups/{gid}/log/consistency?first=1&second=99")
    check("out-of-range size rejected", status == 409
          and err.get("error") == "size_out_of_range", f"status={status} err={err}")
    status, err = call("GET", f"/v1/groups/{gid}/log/consistency?first=abc&second=2")
    check("non-numeric size rejected", status == 400
          and err.get("error") == "bad_range", f"status={status} err={err}")
    status, err = call("GET", f"/v1/groups/{gid}/log/consistency?first=1")
    check("missing size rejected", status == 400
          and err.get("error") == "bad_range", f"status={status} err={err}")
    status, err = call("GET", "/v1/groups/no-such-group/log/consistency?first=0&second=0")
    check("unknown group rejected", status == 404
          and err.get("error") == "unknown_group", f"status={status} err={err}")

    print("-" * 60)
    if _failures:
        print(f"VERIFY FAILED ({len(_failures)} check(s)): {', '.join(_failures)}")
        return 1
    print("VERIFY PASSED: all threshold/idempotency/chain-head/merkle checks OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
