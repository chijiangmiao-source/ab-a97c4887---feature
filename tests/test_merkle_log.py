"""Acceptance tests for the per-group RFC 9162 Merkle log.

The verifier used here is deliberately independent of ``app.merkle``: it is
a line-by-line transcription of RFC 9162 section 2.1.4.2 (bis of RFC
6962), plus independent leaf/MTH construction from the documented leaf
byte string. If the service's proofs only passed its own verifier these
tests would still fail.
"""
from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request

import pytest

from app import crypto, merkle, service
from app.server import build_server
from app.service import ApiError
from app.store import Store

from .helpers import generate_keys, signature_entry

GENESIS = crypto.GENESIS_DIGEST
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


# --------------------------------------------------------------------------
# independent RFC 9162 machinery (does NOT import app.merkle)
# --------------------------------------------------------------------------

def ind_leaf_hash(gid: str, seq: int, pkg_digest: str) -> bytes:
    leaf_input = (
        b"LXe-ConfigSeal-MerkleLog/v1" + b"\x00"
        + len(gid.encode()).to_bytes(2, "big") + gid.encode()
        + seq.to_bytes(8, "big") + bytes.fromhex(pkg_digest)
    )
    return hashlib.sha256(b"\x00" + leaf_input).digest()


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ind_mth(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    n = len(leaves)
    k = 1 << ((n - 1).bit_length() - 1)
    return _h(b"\x01" + ind_mth(leaves[:k]) + ind_mth(leaves[k:]))


def ind_verify(first: int, second: int, first_hash: bytes, second_hash: bytes,
               path: list[bytes]) -> bool:
    """RFC 9162 §2.1.4.2, with the two well-defined degenerate answers."""
    if first == second:
        return path == [] and first_hash == second_hash
    if first == 0:
        return path == []
    if not path:
        return False
    p = list(path)
    if first & (first - 1) == 0:
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
            fr = _h(b"\x01" + c + fr)
            sr = _h(b"\x01" + c + sr)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _h(b"\x01" + sr + c)
        fn >>= 1
        sn >>= 1
    return fr == first_hash and sr == second_hash and sn == 0


# --------------------------------------------------------------------------
# fixtures / helpers
# --------------------------------------------------------------------------

@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "seal.db"))
    yield s
    s.close()


def _make_group(store, gid="run-2026-09", nkeys=3, threshold=2):
    keys = generate_keys(nkeys)
    status, body = service.create_group(store, {
        "group_id": gid, "threshold": threshold,
        "public_keys": [k[2] for k in keys],
    })
    assert status == 201
    return gid, keys


def _submit(store, gid, keys, op_id, prev, seq, config, signers=(0, 1)):
    sigs = [signature_entry(keys[i][0], keys[i][1], gid, prev, seq, config)
            for i in signers]
    return service.submit_package(store, gid, {
        "op_id": op_id, "prev_digest": prev, "seq": seq,
        "config": config, "signatures": sigs,
    })


def _grow(store, gid, keys, n):
    """Confirm n packages; return [(seq, digest, body), ...]."""
    out = []
    prev = GENESIS
    for i in range(1, n + 1):
        config = f"cfg-{i}"
        body = {
            "op_id": f"op-{i}", "prev_digest": prev, "seq": i,
            "config": config,
            "signatures": [signature_entry(keys[j][0], keys[j][1], gid, prev, i, config)
                           for j in (0, 1)],
        }
        _, p = service.submit_package(store, gid, json.loads(json.dumps(body)))
        out.append((p["seq"], p["digest"], body))
        prev = p["digest"]
    return out


def _expected_log(gid, packages):
    leaves = [ind_leaf_hash(gid, item[0], item[1]) for item in packages]
    return leaves, ind_mth(leaves).hex()


def _check_consistency(store, gid, packages, first, second):
    """Fetch a proof and verify it with the INDEPENDENT verifier."""
    status, body = service.get_consistency(
        store, gid, {"first": str(first), "second": str(second)}
    )
    assert status == 200
    leaves, _ = _expected_log(gid, packages)
    first_root = ind_mth(leaves[:first]).hex()
    second_root = ind_mth(leaves[:second]).hex()
    assert body["first_root_hash"] == first_root
    assert body["second_root_hash"] == second_root
    path = [bytes.fromhex(h) for h in body["consistency"]]
    assert ind_verify(first, second,
                      bytes.fromhex(first_root), bytes.fromhex(second_root), path)
    return body


# --------------------------------------------------------------------------
# cumulative root tracking on the existing interfaces
# --------------------------------------------------------------------------

def test_empty_group_advertises_empty_log(store):
    _, body = service.create_group(store, {
        "group_id": "g", "threshold": 1,
        "public_keys": [k[2] for k in generate_keys(2)],
    })
    assert body["log"] == {"size": 0, "root_hash": EMPTY_ROOT}
    status, info = service.get_group(store, "g")
    assert status == 200 and info["log"] == {"size": 0, "root_hash": EMPTY_ROOT}


def test_root_advances_with_each_confirmation(store):
    gid, keys = _make_group(store)
    packages = _grow(store, gid, keys, 6)  # non-power-of-two history
    leaves, expected_root = _expected_log(gid, packages)

    _, info = service.get_group(store, gid)
    assert info["log"] == {"size": 6, "root_hash": expected_root}
    _, listing = service.list_packages(store, gid)
    assert listing["log"] == {"size": 6, "root_hash": expected_root}

    # per-confirmation responses carry the size/root current at that moment
    status, p1 = _submit(store, gid, keys, "extra", packages[-1][1], 7, "cfg-7")
    assert status == 201 and p1["log"]["size"] == 7
    assert p1["log"]["root_hash"] == ind_mth(leaves[:7] + [
        ind_leaf_hash(gid, 7, p1["digest"])]).hex()


def test_leaf_uses_group_seq_digest_but_not_config_text(store):
    """Two groups with the same package digests still get different roots
    (group id is in the leaf); the root needs no config text to recompute."""
    gid_a, keys_a = _make_group(store, "group-a")
    gid_b, keys_b = _make_group(store, "group-b")
    _, a1 = _submit(store, gid_a, keys_a, "op-1", GENESIS, 1, "same-config")
    # produce the identical digest in group b by signing the same fields
    _, b1 = _submit(store, gid_b, keys_b, "op-1", GENESIS, 1, "same-config")
    # digests differ per group (group id is in the signed message too)...
    # ...but in any case roots must not be comparable across groups:
    root_a = service.get_group(store, gid_a)[1]["log"]["root_hash"]
    root_b = service.get_group(store, gid_b)[1]["log"]["root_hash"]
    assert root_a != root_b
    # leaf hash recomputes without config
    assert bytes.fromhex(merkle.leaf_hash(gid_a, 1, a1["digest"])) == ind_leaf_hash(
        gid_a, 1, a1["digest"])


def test_replay_validation_failure_and_conflict_do_not_change_root(store):
    gid, keys = _make_group(store)
    packages = _grow(store, gid, keys, 2)
    _, before = service.get_group(store, gid)
    root_before = before["log"]

    # replay the FIRST op after the log has already grown to size 2:
    # the receipt carries the immutable as-of-commit snapshot (size 1),
    # not the current head -- and the current root is untouched.
    body = json.loads(json.dumps(packages[0][2]))
    status, replay = service.submit_package(store, gid, body)
    assert status == 200 and replay["replay"] is True
    assert replay["log"] == {
        "size": 1,
        "root_hash": _expected_log(gid, packages[:1])[1],
    }
    assert service.get_group(store, gid)[1]["log"] == root_before

    # threshold shortfall
    with pytest.raises(ApiError):
        _submit(store, gid, keys, "op-thin", packages[-1][1], 3, "x", signers=(0,))
    # op_id conflict
    with pytest.raises(ApiError):
        _submit(store, gid, keys, "op-1", GENESIS, 1, "tampered")
    # stale predecessor
    with pytest.raises(ApiError):
        _submit(store, gid, keys, "op-stale", GENESIS, 1, "z")

    assert service.get_group(store, gid)[1]["log"] == root_before


def test_race_losers_do_not_change_root(store):
    gid, keys = _make_group(store)
    packages = _grow(store, gid, keys, 1)
    root_before = service.get_group(store, gid)[1]["log"]
    errors = []

    def attempt(i):
        try:
            _submit(store, gid, keys, f"op-race-{i}", packages[-1][1], 2, f"fork-{i}")
        except ApiError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(errors) == 7
    root_after = service.get_group(store, gid)[1]["log"]
    assert root_after["size"] == 2 and root_after["root_hash"] != root_before["root_hash"]
    # exactly one leaf appended: recompute independent root of size 2
    _, winner = service.list_packages(store, gid)
    pkgs = [(p["seq"], p["digest"]) for p in winner["packages"]]
    assert _expected_log(gid, pkgs)[1] == root_after["root_hash"]


# --------------------------------------------------------------------------
# consistency proofs
# --------------------------------------------------------------------------

@pytest.mark.parametrize("n,first,second", [
    (8, 1, 2), (8, 2, 3), (8, 3, 4), (8, 3, 6), (8, 1, 8),
    (8, 4, 8), (8, 5, 8), (8, 6, 7), (8, 7, 8), (9, 6, 9),
    (7, 1, 7), (7, 2, 7), (7, 3, 7), (7, 5, 7), (5, 3, 5),
])
def test_consistency_proofs_verify_independently(store, n, first, second):
    gid, keys = _make_group(store)
    packages = _grow(store, gid, keys, n)
    _check_consistency(store, gid, packages, first, second)


def test_consistency_is_minimal_and_canonical(store):
    import math
    gid, keys = _make_group(store)
    n = 8
    packages = _grow(store, gid, keys, n)
    for first in range(1, n):
        body = _check_consistency(store, gid, packages, first, n)
        assert len(body["consistency"]) <= math.ceil(math.log2(n)) + 1
    # canonical vectors for the RFC 7-leaf style boundary
    body36 = _check_consistency(store, gid, packages, 3, 6)
    body36_again = service.get_consistency(
        store, gid, {"first": "3", "second": "6"})[1]
    assert body36["consistency"] == body36_again["consistency"]


def test_empty_prefix_is_deterministic(store):
    gid, keys = _make_group(store)
    packages = _grow(store, gid, keys, 3)
    leaves, root3 = _expected_log(gid, packages)
    status, body = service.get_consistency(store, gid, {"first": "0", "second": "3"})
    assert status == 200
    assert body["first_root_hash"] == EMPTY_ROOT
    assert body["second_root_hash"] == root3
    assert body["consistency"] == []
    # independent verifier: empty prefix with empty path is accepted
    assert ind_verify(0, 3, bytes.fromhex(EMPTY_ROOT), bytes.fromhex(root3), [])
    # and a non-empty path would be rejected for the empty prefix
    assert not ind_verify(0, 3, bytes.fromhex(EMPTY_ROOT), bytes.fromhex(root3),
                          [leaves[0]])


def test_equal_sizes_are_deterministic(store):
    gid, keys = _make_group(store)
    packages = _grow(store, gid, keys, 4)
    _, root4 = _expected_log(gid, packages)
    for size in (0, 1, 2, 3, 4):
        status, body = service.get_consistency(
            store, gid, {"first": str(size), "second": str(size)})
        assert status == 200
        assert body["consistency"] == []
        assert body["first_root_hash"] == body["second_root_hash"]
    status, body = service.get_consistency(store, gid, {"first": "4", "second": "4"})
    assert body["first_root_hash"] == root4


def test_out_of_range_and_bad_sizes_rejected(store):
    gid, keys = _make_group(store)
    _grow(store, gid, keys, 2)

    def expect(params, status_code, code):
        with pytest.raises(ApiError) as e:
            service.get_consistency(store, gid, params)
        assert e.value.status == status_code and e.value.code == code

    expect({"first": "1", "second": "3"}, 409, "log_size_out_of_range")
    expect({"first": "3", "second": "3"}, 409, "log_size_out_of_range")
    expect({"first": "2", "second": "1"}, 400, "bad_size_order")
    expect({"first": "-1", "second": "1"}, 400, "bad_first")
    expect({"first": "x", "second": "1"}, 400, "bad_first")
    expect({"first": "1"}, 400, "bad_second")
    expect({"second": "1"}, 400, "bad_first")
    expect({"first": "1.5", "second": "2"}, 400, "bad_first")

    with pytest.raises(ApiError) as e:
        service.get_consistency(store, "no-such-group", {"first": "0", "second": "0"})
    assert e.value.status == 404 and e.value.code == "unknown_group"


def test_tampered_proof_fails_verification(store):
    gid, keys = _make_group(store)
    packages = _grow(store, gid, keys, 6)
    leaves, _ = _expected_log(gid, packages)
    body = service.get_consistency(store, gid, {"first": "3", "second": "6"})[1]
    path = [bytes.fromhex(h) for h in body["consistency"]]
    assert path  # non-empty for 3->6
    fr = bytes.fromhex(body["first_root_hash"])
    sr = bytes.fromhex(body["second_root_hash"])
    assert ind_verify(3, 6, fr, sr, path)

    # flip every sibling, one at a time: each must fail
    for i in range(len(path)):
        broken = list(path)
        broken[i] = hashlib.sha256(b"tampered" + bytes([i])).digest()
        assert not ind_verify(3, 6, fr, sr, broken)
    # truncation / extension / wrong roots all fail
    assert not ind_verify(3, 6, fr, sr, path[:-1])
    assert not ind_verify(3, 6, fr, sr, path + [leaves[0]])
    assert not ind_verify(3, 6, hashlib.sha256(b"fake").digest(), sr, path)
    assert not ind_verify(3, 6, fr, hashlib.sha256(b"fake").digest(), path)


def test_proof_does_not_cross_groups(store):
    gid_a, keys_a = _make_group(store, "group-a")
    gid_b, keys_b = _make_group(store, "group-b")
    _grow(store, gid_a, keys_a, 4)
    _grow(store, gid_b, keys_b, 6)
    body_a = service.get_consistency(store, gid_a, {"first": "2", "second": "4"})[1]
    body_b = service.get_consistency(store, gid_b, {"first": "3", "second": "6"})[1]
    # group A's sibling path verified against group B's roots must fail
    assert not ind_verify(
        2, 4, bytes.fromhex(body_b["first_root_hash"]),
        bytes.fromhex(body_a["second_root_hash"]),
        [bytes.fromhex(h) for h in body_a["consistency"]],
    )
    assert not ind_verify(
        3, 6, bytes.fromhex(body_a["first_root_hash"]),
        bytes.fromhex(body_b["second_root_hash"]),
        [bytes.fromhex(h) for h in body_b["consistency"]],
    )
    # sanity: each verifies against its own group
    for body, f, s in ((body_a, 2, 4), (body_b, 3, 6)):
        assert ind_verify(f, s, bytes.fromhex(body["first_root_hash"]),
                          bytes.fromhex(body["second_root_hash"]),
                          [bytes.fromhex(h) for h in body["consistency"]])


# --------------------------------------------------------------------------
# restart: root and proof are rebuilt identically from confirmed packages
# --------------------------------------------------------------------------

def test_restart_rebuilds_same_root_and_proof(tmp_path):
    db = str(tmp_path / "seal.db")
    s1 = Store(db)
    gid, keys = _make_group(s1, "g-restart")
    packages = _grow(s1, gid, keys, 6)
    before_root = service.get_group(s1, gid)[1]["log"]
    before_proof = service.get_consistency(s1, gid, {"first": "3", "second": "6"})[1]
    s1.close()

    s2 = Store(db)
    try:
        after_root = service.get_group(s2, gid)[1]["log"]
        assert after_root == before_root
        # independently recomputed
        assert _expected_log(gid, packages)[1] == after_root["root_hash"]
        after_proof = service.get_consistency(s2, gid, {"first": "3", "second": "6"})[1]
        assert after_proof == before_proof
        # chain can continue, log extends
        prev = packages[-1][1]
        status, p7 = _submit(s2, gid, keys, "op-7", prev, 7, "cfg-7")
        assert status == 201
        pkgs = packages + [(7, p7["digest"])]
        assert service.get_group(s2, gid)[1]["log"]["root_hash"] == \
            _expected_log(gid, pkgs)[1]
    finally:
        s2.close()


def test_restart_backfills_log_into_legacy_receipts(tmp_path):
    """Receipts written by a build without the Merkle log gain the immutable
    as-of-commit snapshot on the first restart after upgrade."""
    db = str(tmp_path / "seal.db")
    s1 = Store(db)
    gid, keys = _make_group(s1, "g-legacy")
    packages = _grow(s1, gid, keys, 3)
    # strip every log artefact, as a pre-upgrade database would look
    conn = s1._conn  # same process: reuse the connection for setup
    conn.execute("DELETE FROM log_leaves")
    conn.execute("DELETE FROM log_state")
    rows = conn.execute("SELECT group_id, op_id, response_json FROM receipts").fetchall()
    for r in rows:
        payload = json.loads(r["response_json"])
        payload.pop("log", None)
        conn.execute("UPDATE receipts SET response_json=? WHERE group_id=? AND op_id=?",
                     (json.dumps(payload), r["group_id"], r["op_id"]))
    conn.commit()
    s1.close()

    s2 = Store(db)
    try:
        status, replay = service.submit_package(
            s2, gid, json.loads(json.dumps(packages[0][2])))
        assert status == 200 and replay["replay"] is True
        assert replay["log"] == {
            "size": 1, "root_hash": _expected_log(gid, packages[:1])[1]}
        assert service.get_group(s2, gid)[1]["log"]["root_hash"] == \
            _expected_log(gid, packages)[1]
    finally:
        s2.close()


# --------------------------------------------------------------------------
# HTTP: route, deterministic edge cases and tamper failure over the wire
# --------------------------------------------------------------------------

def test_http_consistency_end_to_end(tmp_path):
    httpd, store = build_server("127.0.0.1", 0, str(tmp_path / "http.db"))
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"

    def call(method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        keys = generate_keys(3)
        status, created = call("POST", "/v1/groups", {
            "group_id": "http-g", "threshold": 2,
            "public_keys": [k[2] for k in keys],
        })
        assert status == 201 and created["log"]["size"] == 0

        packages = []
        prev = GENESIS
        for i in range(1, 7):
            body = {
                "op_id": f"op-{i}", "prev_digest": prev, "seq": i,
                "config": f"cfg-{i}",
                "signatures": [signature_entry(keys[j][0], keys[j][1],
                                               "http-g", prev, i, f"cfg-{i}")
                               for j in (0, 1)],
            }
            status, p = call("POST", "/v1/groups/http-g/packages", body)
            assert status == 201 and p["log"]["size"] == i
            packages.append((i, p["digest"]))
            prev = p["digest"]

        leaves, expected_root = _expected_log("http-g", packages)

        status, info = call("GET", "/v1/groups/http-g")
        assert status == 200
        # old interface fields still present (regression)
        assert set(info) >= {"group_id", "threshold", "key_ids", "head", "log"}
        assert info["head"] == {"seq": 6, "digest": packages[-1][1]}
        assert info["log"] == {"size": 6, "root_hash": expected_root}

        # valid proof at a non-power-of-two boundary verifies independently
        status, proof = call("GET", "/v1/groups/http-g/consistency?first=3&second=6")
        assert status == 200
        assert ind_verify(3, 6, bytes.fromhex(proof["first_root_hash"]),
                          bytes.fromhex(proof["second_root_hash"]),
                          [bytes.fromhex(h) for h in proof["consistency"]])

        # empty prefix and equal size
        status, empty = call("GET", "/v1/groups/http-g/consistency?first=0&second=6")
        assert status == 200 and empty["consistency"] == []
        status, same = call("GET", "/v1/groups/http-g/consistency?first=6&second=6")
        assert status == 200 and same["consistency"] == []
        assert same["first_root_hash"] == expected_root

        # rejections over HTTP
        status, err = call("GET", "/v1/groups/http-g/consistency?first=1&second=9")
        assert status == 409 and err["error"] == "log_size_out_of_range"
        status, err = call("GET", "/v1/groups/http-g/consistency?first=5&second=2")
        assert status == 400 and err["error"] == "bad_size_order"
        status, err = call("GET", "/v1/groups/missing/consistency?first=0&second=0")
        assert status == 404 and err["error"] == "unknown_group"

        # tampered proof served bytes would fail verification
        broken = list(proof["consistency"])
        broken[0] = hashlib.sha256(b"wire-tamper").hexdigest()
        assert not ind_verify(3, 6, bytes.fromhex(proof["first_root_hash"]),
                              bytes.fromhex(proof["second_root_hash"]),
                              [bytes.fromhex(h) for h in broken])

        # old read interface regression: packages listing still works + has log
        status, listing = call("GET", "/v1/groups/http-g/packages")
        assert status == 200 and len(listing["packages"]) == 6
        assert listing["log"]["root_hash"] == expected_root
    finally:
        httpd.shutdown()
        httpd.server_close()
        store.close()
