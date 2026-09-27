#!/usr/bin/env python3
"""Acceptance verifier for the ``verify`` compose service.

Runs entirely over HTTP against a running seal server:

  0. waits for /healthz, builds + API smoke (group create, get)
  1. threshold shortfall is rejected (422) and leaves history untouched
  2. valid first package: digest/seq/unique head are exactly as expected
  3. idempotent retransmission replays the same receipt, creates no history
  4. same op_id with a changed payload conflicts (409)
  5. concurrent submissions racing for the same predecessor: exactly one wins
  6. per-group RFC 9162 Merkle log: independently recomputed roots,
     consistency proofs (incl. non-power-of-two boundaries), empty prefix
     and equal-size edge cases, tampered-proof rejection, cross-group
     rejection, out-of-range rejection, old read/confirm interface
     regression.

Exits 0 only if every check passes.
"""
from __future__ import annotations

import hashlib
import json
import math
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


def package_body(keys, gid, op_id, prev, seq, config, idxs):
    return {
        "op_id": op_id, "prev_digest": prev, "seq": seq, "config": config,
        "signatures": [
            {"key_id": keys[i][1], "signature": sig(keys[i][0], gid, prev, seq, config)}
            for i in idxs
        ],
    }


# --------------------------------------------------------------------------
# Independent RFC 9162 (bis of RFC 6962) verifier -- does not reuse any
# service-side code beyond the documented leaf byte string.
# --------------------------------------------------------------------------

def _hh(parts: bytes) -> bytes:
    return hashlib.sha256(parts).digest()


def expected_leaf(gid: str, seq: int, pkg_digest: str) -> bytes:
    leaf_input = (
        b"LXe-ConfigSeal-MerkleLog/v1" + b"\x00"
        + len(gid.encode("utf-8")).to_bytes(2, "big") + gid.encode("utf-8")
        + seq.to_bytes(8, "big") + bytes.fromhex(pkg_digest)
    )
    return _hh(b"\x00" + leaf_input)


def expected_root(gid: str, packages: list[tuple[int, str]]) -> bytes:
    """MTH per RFC 9162 §2.1.1; MTH({}) = HASH()."""
    leaves = [expected_leaf(gid, s, d) for s, d in packages]

    def mth(ls: list[bytes]) -> bytes:
        if not ls:
            return hashlib.sha256(b"").digest()
        if len(ls) == 1:
            return ls[0]
        k = 1 << ((len(ls) - 1).bit_length() - 1)
        return _hh(b"\x01" + mth(ls[:k]) + mth(ls[k:]))

    return mth(leaves)


def verify_consistency(first: int, second: int, first_hash: bytes,
                       second_hash: bytes, path: list[bytes]) -> bool:
    """RFC 9162 §2.1.4.2, with the two well-defined degenerate answers."""
    if first == second:
        return path == [] and first_hash == second_hash
    if first == 0:
        return path == []
    if not path:
        return False
    p = list(path)
    if first & (first - 1) == 0:  # exact power of two: prepend old root
        p = [first_hash] + p
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = p[0]
    for c in p[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = _hh(b"\x01" + c + fr)
            sr = _hh(b"\x01" + c + sr)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _hh(b"\x01" + sr + c)
        fn >>= 1
        sn >>= 1
    return fr == first_hash and sr == second_hash and sn == 0


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

    # -- 2. valid first package ---------------------------------------------
    p1_body = package_body(keys, gid, "op-1", crypto.GENESIS_DIGEST, 1, "field=1500V", (0, 1))
    status, p1 = call("POST", f"/v1/groups/{gid}/packages", p1_body)
    expected1 = crypto.package_digest(gid, crypto.GENESIS_DIGEST, 1, "field=1500V")
    check("valid first package confirmed", status == 201 and p1["seq"] == 1
          and p1["digest"] == expected1, f"status={status} p1={p1}")
    status, info = call("GET", f"/v1/groups/{gid}")
    check("unique chain head == package 1",
          info["head"] == {"seq": 1, "digest": expected1}, f"head={info.get('head')}")

    # -- 3. idempotent retransmission ---------------------------------------
    raw = json.dumps(p1_body).encode("utf-8")
    status, replay = call("POST", f"/v1/groups/{gid}/packages", raw=raw)
    check("idempotent retransmission replays receipt",
          status == 200 and replay.get("replay") is True
          and replay["digest"] == expected1 and replay["seq"] == 1,
          f"status={status} replay={replay}")
    status, listing = call("GET", f"/v1/groups/{gid}/packages")
    check("retry wrote no extra history",
          len(listing["packages"]) == 1, f"n={len(listing['packages'])}")

    # -- 4. op_id reused with a different payload conflicts -----------------
    # Properly signed, well-formed, but the op_id is already confirmed for a
    # different payload -> hard 409, no new history.
    conflict = package_body(keys, gid, "op-1", crypto.GENESIS_DIGEST, 1, "field=9999V", (0, 1))
    status, err = call("POST", f"/v1/groups/{gid}/packages", conflict)
    check("same op_id different payload conflicts",
          status == 409 and err.get("error") == "op_id_conflict",
          f"status={status} err={err}")

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

    status, listing = call("GET", f"/v1/groups/{gid}/packages")
    check("history holds exactly two linear packages",
          [p["seq"] for p in listing["packages"]] == [1, 2]
          and listing["packages"][1]["prev_digest"] == expected1
          and listing["packages"][1]["digest"] == winner_digest,
          f"seqs={[p['seq'] for p in listing['packages']]}")

    # -- 6. RFC 9162 per-group Merkle log -----------------------------------
    packages = [(p["seq"], p["digest"]) for p in listing["packages"]]

    # old interface fields are all still there, now with log size/root attached
    check("old group interface regression + log attached",
          status == 200 and set(info) >= {"group_id", "threshold", "key_ids", "head", "log"}
          and info["log"]["size"] == 2
          and info["log"]["root_hash"] == expected_root(gid, packages).hex(),
          f"info keys={sorted(info)} log={info.get('log')}")
    check("old packages interface regression + log attached",
          len(listing["packages"]) == 2 and listing["log"]["size"] == 2
          and listing["log"]["root_hash"] == expected_root(gid, packages).hex(),
          f"log={listing.get('log')}")

    # grow to a non-power-of-two size, checking every confirmation's log view
    prev = winner_digest
    pkg_raw = {}
    for seq in range(3, 7):
        body = package_body(keys, gid, f"op-log-{seq}", prev, seq, f"field=1{seq}00V", (0, 1))
        raw = json.dumps(body).encode("utf-8")
        pkg_raw[seq] = raw
        st, pkg = call("POST", f"/v1/groups/{gid}/packages", raw=raw)
        packages.append((seq, pkg["digest"]))
        prev = pkg["digest"]
        want_root = expected_root(gid, packages).hex()
        check(f"package {seq} confirmation carries log size/root",
              st == 201 and pkg["log"] == {"size": seq, "root_hash": want_root}
              and pkg["digest"] == crypto.package_digest(
                  gid, packages[-2][1], seq, f"field=1{seq}00V"),
              f"st={st} log={pkg.get('log')} want={want_root}")

    root6 = expected_root(gid, packages)
    root_at = {seq: expected_root(gid, packages[:seq]).hex() for seq in range(3, 7)}
    bound = math.ceil(math.log2(6)) + 1

    def proof(first, second):
        return call("GET", f"/v1/groups/{gid}/consistency?first={first}&second={second}")

    # non-power-of-two boundary 3 -> 6 independently verified
    st, cp = proof(3, 6)
    path = [bytes.fromhex(h) for h in cp.get("consistency", [])]
    fr = bytes.fromhex(cp.get("first_root_hash", ""))
    sr = bytes.fromhex(cp.get("second_root_hash", ""))
    ok_proof = (
        st == 200
        and fr == expected_root(gid, packages[:3]) and sr == root6
        and len(path) <= bound
        and verify_consistency(3, 6, fr, sr, path)
    )
    check("consistency proof 3->6 verifies independently (non-power-of-two)",
          ok_proof, f"st={st} len={len(path)} bound={bound} cp={cp}")

    # canonical/ordering: same request gives byte-identical proof
    st2, cp2 = proof(3, 6)
    check("consistency proof is deterministic", st2 == 200 and cp2 == cp)

    # empty prefix: deterministic empty path, roots returned
    st, emp = proof(0, 6)
    check("empty prefix 0->6 is deterministic",
          st == 200 and emp["consistency"] == []
          and emp["first_root_hash"] == hashlib.sha256(b"").hexdigest()
          and emp["second_root_hash"] == root6.hex()
          and verify_consistency(0, 6, hashlib.sha256(b"").digest(), root6, []),
          f"st={st} emp={emp}")
    # equal sizes: deterministic empty path with equal roots
    st, same = proof(6, 6)
    check("equal sizes 6->6 is deterministic",
          st == 200 and same["consistency"] == []
          and same["first_root_hash"] == same["second_root_hash"] == root6.hex(),
          f"st={st} same={same}")
    st, same0 = proof(0, 0)
    check("zero->zero on a non-empty log is deterministic",
          st == 200 and same0["consistency"] == []
          and same0["first_root_hash"] == hashlib.sha256(b"").hexdigest(),
          f"st={st} same0={same0}")

    # power-of-two old size boundary 4 -> 6
    st, cp46 = proof(4, 6)
    check("consistency proof 4->6 (power-of-two prefix) verifies",
          st == 200 and verify_consistency(
              4, 6, bytes.fromhex(cp46["first_root_hash"]),
              bytes.fromhex(cp46["second_root_hash"]),
              [bytes.fromhex(h) for h in cp46["consistency"]]),
          f"st={st} cp={cp46}")

    # tampered proof must fail verification (flip each sibling in turn)
    tamper_fails = all(
        not verify_consistency(
            3, 6, fr, sr,
            [hashlib.sha256(b"tamper" + bytes([i])).digest() if i == j else h
             for j, h in enumerate(path)])
        for i in range(len(path))
    )
    check("tampered consistency proof fails verification",
          tamper_fails and path, f"path len={len(path)}")
    trunc_fails = not verify_consistency(3, 6, fr, sr, path[:-1])
    check("truncated consistency proof fails verification", trunc_fails, "")
    wrong_root = not verify_consistency(
        3, 6, hashlib.sha256(b"bogus-old-root").digest(), sr, path)
    check("proof with forged old root fails verification", wrong_root, "")

    # cross-group: a second group's proof must not verify against this group
    gid2 = f"{gid}-peer"
    keys2 = make_keys(3)
    st, created2 = call("POST", "/v1/groups", {
        "group_id": gid2, "threshold": 2, "public_keys": [k[2] for k in keys2],
    })
    peer_pkgs = []
    prev2 = crypto.GENESIS_DIGEST
    for seq in range(1, 5):
        b = package_body(keys2, gid2, f"p-op-{seq}", prev2, seq, f"peer-{seq}", (0, 1))
        st, pkg = call("POST", f"/v1/groups/{gid2}/packages", b)
        peer_pkgs.append((seq, pkg["digest"]))
        prev2 = pkg["digest"]
    st, peer_cp = call("GET", f"/v1/groups/{gid2}/consistency?first=2&second=4")
    cross_ok_own = verify_consistency(
        2, 4, bytes.fromhex(peer_cp["first_root_hash"]),
        bytes.fromhex(peer_cp["second_root_hash"]),
        [bytes.fromhex(h) for h in peer_cp["consistency"]])
    cross_rejected = not verify_consistency(
        2, 4, fr, sr, [bytes.fromhex(h) for h in peer_cp["consistency"]])
    # and group A proof verified against group B's advertised roots must fail
    cross_rejected2 = not verify_consistency(
        3, 6, bytes.fromhex(peer_cp["first_root_hash"]),
        bytes.fromhex(peer_cp["second_root_hash"]), path)
    check("consistency proofs are group-scoped (cross-group rejected)",
          st == 200 and cross_ok_own and cross_rejected and cross_rejected2, "")

    # out-of-range / malformed sizes are rejected deterministically
    st, err = proof(3, 7)
    check("second beyond confirmed log rejected",
          st == 409 and err.get("error") == "log_size_out_of_range", f"st={st} err={err}")
    st, err = proof(7, 7)
    check("both sizes beyond confirmed log rejected",
          st == 409 and err.get("error") == "log_size_out_of_range", f"st={st} err={err}")
    st, err = proof(5, 2)
    check("first > second rejected", st == 400 and err.get("error") == "bad_size_order",
          f"st={st} err={err}")
    st, err = call("GET", "/v1/groups/no-such-group/consistency?first=0&second=1")
    check("consistency for unknown group rejected",
          st == 404 and err.get("error") == "unknown_group", f"st={st} err={err}")

    # idempotent retransmission after the log kept growing: the receipt
    # returns the IMMUTABLE log snapshot as of that confirmation (size 3),
    # while the current head remains at size 6 -- neither root changes.
    st, replay_old = call("POST", f"/v1/groups/{gid}/packages", raw=pkg_raw[3])
    st2, info_after = call("GET", f"/v1/groups/{gid}")
    check("old op replay returns its as-of-commit log snapshot",
          st == 200 and replay_old.get("replay") is True
          and replay_old["seq"] == 3
          and replay_old["log"] == {"size": 3, "root_hash": root_at[3]},
          f"st={st} replay={replay_old.get('seq')} log={replay_old.get('log')}")
    check("replay after log growth changes no current root",
          st2 == 200 and info_after["log"] == {"size": 6, "root_hash": root6.hex()},
          f"log={info_after.get('log')}")
    st, replay2 = call("POST", f"/v1/groups/{gid}/packages", raw=pkg_raw[6])
    check("latest op replay returns identical current snapshot",
          st == 200 and replay2.get("replay") is True
          and replay2["log"] == {"size": 6, "root_hash": root6.hex()},
          f"st={st} log={replay2.get('log')}")

    print("-" * 60)
    if _failures:
        print(f"VERIFY FAILED ({len(_failures)} check(s)): {', '.join(_failures)}")
        return 1
    print("VERIFY PASSED: all threshold/idempotency/chain-head checks OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
