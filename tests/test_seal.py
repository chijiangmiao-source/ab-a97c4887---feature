"""Acceptance tests for the threshold-sealed config package service."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from app import crypto, merkle, service
from app.server import build_server
from app.service import ApiError
from app.store import Store

from .helpers import generate_keys, sign, signature_entry

GENESIS = crypto.GENESIS_DIGEST


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "seal.db"))
    yield s
    s.close()


@pytest.fixture()
def group(store):
    """A 2-of-3 seal group; returns (group_id, keys)."""
    keys = generate_keys(3)
    status, body = service.create_group(store, {
        "group_id": "run-2026-09",
        "threshold": 2,
        "public_keys": [k[2] for k in keys],
    })
    assert status == 201
    assert body["head"] == {"seq": 0, "digest": GENESIS}
    return "run-2026-09", keys


def _submit(store, gid, keys, op_id, prev, seq, config, signers=(0, 1)):
    sigs = [signature_entry(keys[i][0], keys[i][1], gid, prev, seq, config) for i in signers]
    return service.submit_package(store, gid, {
        "op_id": op_id, "prev_digest": prev, "seq": seq,
        "config": config, "signatures": sigs,
    })


def _err(excinfo):
    return excinfo.value.status, excinfo.value.code


# --------------------------------------------------------------------------
# group registration
# --------------------------------------------------------------------------

def test_create_group_rejects_bad_key_counts(store):
    keys = generate_keys(2)
    for pubs in ([keys[0][2]], [k[2] for k in generate_keys(9)]):
        with pytest.raises(ApiError) as e:
            service.create_group(store, {"group_id": "g", "threshold": 1, "public_keys": pubs})
        assert _err(e) == (400, "bad_key_count")


def test_create_group_rejects_duplicate_and_nonunique_keys(store):
    keys = generate_keys(2)
    with pytest.raises(ApiError) as e:
        service.create_group(store, {
            "group_id": "g", "threshold": 1,
            "public_keys": [keys[0][2], keys[0][2]],
        })
    assert _err(e) == (400, "duplicate_key")


def test_create_group_rejects_bad_threshold_and_bad_key(store):
    keys = generate_keys(2)
    with pytest.raises(ApiError) as e:
        service.create_group(store, {
            "group_id": "g", "threshold": 3, "public_keys": [k[2] for k in keys],
        })
    assert _err(e) == (400, "bad_threshold")
    with pytest.raises(ApiError) as e:
        service.create_group(store, {
            "group_id": "g", "threshold": 1, "public_keys": [keys[0][2], "not-a-key"],
        })
    assert _err(e) == (400, "bad_key")


def test_create_group_is_not_idempotent_overwrite(store):
    keys = generate_keys(2)
    body = {"group_id": "g", "threshold": 2, "public_keys": [k[2] for k in keys]}
    assert service.create_group(store, body)[0] == 201
    with pytest.raises(ApiError) as e:
        service.create_group(store, body)
    assert _err(e) == (409, "group_exists")


# --------------------------------------------------------------------------
# happy path: first package, continuation, digest/seq/unique head
# --------------------------------------------------------------------------

def test_first_and_continuation_packages(store, group):
    gid, keys = group

    status, p1 = _submit(store, gid, keys, "op-1", GENESIS, 1, "field=1500V")
    assert status == 201
    assert p1["seq"] == 1
    assert p1["digest"] == crypto.package_digest(gid, GENESIS, 1, "field=1500V")
    assert p1["replay"] is False

    status, p2 = _submit(store, gid, keys, "op-2", p1["digest"], 2, "field=1600V")
    assert status == 201
    assert p2["seq"] == 2
    assert p2["digest"] == crypto.package_digest(gid, p1["digest"], 2, "field=1600V")
    assert p2["prev_digest"] == p1["digest"]

    # unique chain head is the second package
    _, info = service.get_group(store, gid)
    assert info["head"] == {"seq": 2, "digest": p2["digest"]}

    # full chain is linear and recoverable
    _, listing = service.list_packages(store, gid)
    chain = listing["packages"]
    assert [p["seq"] for p in chain] == [1, 2]
    assert chain[0]["prev_digest"] == GENESIS
    assert chain[1]["prev_digest"] == chain[0]["digest"]


def test_restart_recovers_unique_chain_head(tmp_path, group):
    db = str(tmp_path / "seal.db")
    s1 = Store(db)
    keys = generate_keys(3)
    service.create_group(s1, {"group_id": "g", "threshold": 2,
                              "public_keys": [k[2] for k in keys]})
    _, p1 = _submit(s1, "g", keys, "op-1", GENESIS, 1, "a")
    _, p2 = _submit(s1, "g", keys, "op-2", p1["digest"], 2, "b")
    s1.close()

    # restart: head must be recovered from confirmed packages alone
    s2 = Store(db)
    try:
        _, info = service.get_group(s2, "g")
        assert info["head"] == {"seq": 2, "digest": p2["digest"]}
        # and the chain can be extended exactly once from the recovered head
        status, p3 = _submit(s2, "g", keys, "op-3", p2["digest"], 3, "c")
        assert status == 201 and p3["seq"] == 3
    finally:
        s2.close()


# --------------------------------------------------------------------------
# rejections that must not change history
# --------------------------------------------------------------------------

def test_tampered_signature_rejected(store, group):
    gid, keys = group
    good = signature_entry(keys[0][0], keys[0][1], gid, GENESIS, 1, "cfg")
    evil = signature_entry(keys[1][0], keys[1][1], gid, GENESIS, 1, "cfg")
    evil["signature"] = evil["signature"][:-2] + ("00" if not evil["signature"].endswith("00") else "01")
    with pytest.raises(ApiError) as e:
        service.submit_package(store, gid, {
            "op_id": "op-x", "prev_digest": GENESIS, "seq": 1,
            "config": "cfg", "signatures": [good, evil],
        })
    assert _err(e) == (422, "invalid_signature")
    assert service.get_group(store, gid)[1]["head"]["seq"] == 0


def test_signature_over_wrong_fields_rejected(store, group):
    gid, keys = group
    # signature made for seq=2 is presented for seq=1
    sigs = [signature_entry(keys[i][0], keys[i][1], gid, GENESIS, 2, "cfg") for i in (0, 1)]
    with pytest.raises(ApiError) as e:
        service.submit_package(store, gid, {
            "op_id": "op-x", "prev_digest": GENESIS, "seq": 1,
            "config": "cfg", "signatures": sigs,
        })
    assert _err(e) == (422, "invalid_signature")


def test_duplicate_signer_rejected(store, group):
    gid, keys = group
    sig = signature_entry(keys[0][0], keys[0][1], gid, GENESIS, 1, "cfg")
    with pytest.raises(ApiError) as e:
        service.submit_package(store, gid, {
            "op_id": "op-x", "prev_digest": GENESIS, "seq": 1,
            "config": "cfg", "signatures": [sig, sig],
        })
    assert _err(e) == (422, "duplicate_signer")
    assert service.get_group(store, gid)[1]["head"]["seq"] == 0


def test_insufficient_threshold_rejected(store, group):
    gid, keys = group
    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-x", GENESIS, 1, "cfg", signers=(0,))
    assert _err(e) == (422, "insufficient_threshold")
    assert service.get_group(store, gid)[1]["head"]["seq"] == 0


def test_unknown_signer_rejected(store, group):
    gid, keys = group
    stranger = generate_keys(1)[0]
    sigs = [signature_entry(keys[0][0], keys[0][1], gid, GENESIS, 1, "cfg"),
            signature_entry(stranger[0], stranger[1], gid, GENESIS, 1, "cfg")]
    with pytest.raises(ApiError) as e:
        service.submit_package(store, gid, {
            "op_id": "op-x", "prev_digest": GENESIS, "seq": 1,
            "config": "cfg", "signatures": sigs,
        })
    assert _err(e) == (422, "unknown_signer")


def test_stale_predecessor_rejected(store, group):
    gid, keys = group
    _, p1 = _submit(store, gid, keys, "op-1", GENESIS, 1, "a")
    # replaying an already-consumed predecessor must fail and change nothing
    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-2", GENESIS, 1, "b")
    assert _err(e) == (409, "stale_predecessor")
    # skipping ahead must fail too
    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-3", p1["digest"], 3, "b")
    assert _err(e) == (409, "stale_predecessor")
    assert service.get_group(store, gid)[1]["head"] == {"seq": 1, "digest": p1["digest"]}


# --------------------------------------------------------------------------
# idempotency
# --------------------------------------------------------------------------

def test_idempotent_retransmission(store, group):
    gid, keys = group
    body = {
        "op_id": "op-1", "prev_digest": GENESIS, "seq": 1, "config": "cfg",
        "signatures": [signature_entry(keys[i][0], keys[i][1], gid, GENESIS, 1, "cfg")
                       for i in (0, 1)],
    }
    status1, first = service.submit_package(store, gid, body)
    status2, second = service.submit_package(store, gid, json.loads(json.dumps(body)))
    assert status1 == 201 and status2 == 200
    assert second["replay"] is True
    assert second["digest"] == first["digest"] and second["seq"] == first["seq"]
    # history holds exactly one package
    assert len(service.list_packages(store, gid)[1]["packages"]) == 1


def test_op_id_conflict_rejected(store, group):
    gid, keys = group
    _, p1 = _submit(store, gid, keys, "op-1", GENESIS, 1, "a")
    # same op_id, different payload -> hard conflict, no new history
    with pytest.raises(ApiError) as e:
        _submit(store, gid, keys, "op-1", GENESIS, 1, "tampered")
    assert _err(e) == (409, "op_id_conflict")
    _, listing = service.list_packages(store, gid)
    assert len(listing["packages"]) == 1
    assert service.get_group(store, gid)[1]["head"]["digest"] == p1["digest"]


# --------------------------------------------------------------------------
# concurrency: competing forks on the same predecessor
# --------------------------------------------------------------------------

def test_concurrent_fork_exactly_one_winner(store, group):
    gid, keys = group
    results, errors = [], []

    def attempt(i):
        try:
            results.append(_submit(store, gid, keys, f"op-{i}", GENESIS, 1, f"cfg-{i}"))
        except ApiError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 1, f"expected exactly one winner, got {len(results)}"
    assert all(e.code == "stale_predecessor" for e in errors)
    assert len(errors) == 7
    winner = results[0][1]
    assert service.get_group(store, gid)[1]["head"] == {"seq": 1, "digest": winner["digest"]}
    assert len(service.list_packages(store, gid)[1]["packages"]) == 1
    # the Merkle log moved exactly once, to the winner's leaf alone
    log = service.get_group(store, gid)[1]["log"]
    assert log["size"] == 1
    assert log["root"] == merkle.root_hex([merkle.leaf_hash_hex(gid, 1, winner["digest"])])


# --------------------------------------------------------------------------
# Merkle log: leaf append, cumulative root, consistency proofs
# --------------------------------------------------------------------------

def _log(store, gid):
    return service.get_group(store, gid)[1]["log"]


def _expected_root(store, gid, upto=None):
    """Independently recompute the log root from the confirmed packages."""
    packages = service.list_packages(store, gid)[1]["packages"][:upto]
    return merkle.root_hex(
        [merkle.leaf_hash_hex(gid, p["seq"], p["digest"]) for p in packages]
    )


def test_confirm_appends_leaf_and_reports_cumulative_root(store, group):
    gid, keys = group
    assert _log(store, gid) == {"size": 0, "root": merkle.EMPTY_ROOT_HEX}

    status, p1 = _submit(store, gid, keys, "op-1", GENESIS, 1, "a")
    assert status == 201
    assert p1["log"] == {"size": 1, "root": _expected_root(store, gid)}
    assert _log(store, gid) == p1["log"]

    status, p2 = _submit(store, gid, keys, "op-2", p1["digest"], 2, "b")
    assert status == 201
    assert p2["log"] == {"size": 2, "root": _expected_root(store, gid)}
    assert p2["log"]["root"] != p1["log"]["root"]

    # every read interface carries the same log state
    assert _log(store, gid) == p2["log"]
    _, listing = service.list_packages(store, gid)
    assert listing["log"] == p2["log"]


def test_rejected_and_replayed_submissions_do_not_change_root(store, group):
    gid, keys = group
    body = {
        "op_id": "op-1", "prev_digest": GENESIS, "seq": 1, "config": "cfg",
        "signatures": [signature_entry(keys[i][0], keys[i][1], gid, GENESIS, 1, "cfg")
                       for i in (0, 1)],
    }
    status, first = service.submit_package(store, gid, body)
    assert status == 201
    log1 = _log(store, gid)
    assert first["log"] == log1

    # stateless validation failure (threshold shortfall)
    with pytest.raises(ApiError):
        _submit(store, gid, keys, "op-thin", GENESIS, 1, "x", signers=(0,))
    # invalid signature (signed over different fields)
    with pytest.raises(ApiError):
        service.submit_package(store, gid, {
            "op_id": "op-bad", "prev_digest": GENESIS, "seq": 1, "config": "x",
            "signatures": [signature_entry(keys[i][0], keys[i][1], gid, GENESIS, 2, "x")
                           for i in (0, 1)],
        })
    # stale predecessor (loses against the confirmed head)
    with pytest.raises(ApiError):
        _submit(store, gid, keys, "op-stale", GENESIS, 1, "x")
    # op_id conflict
    with pytest.raises(ApiError):
        _submit(store, gid, keys, "op-1", GENESIS, 1, "tampered")
    assert _log(store, gid) == log1

    # idempotent retransmission: same receipt, same log, no new leaf
    status, replay = service.submit_package(store, gid, json.loads(json.dumps(body)))
    assert status == 200 and replay["replay"] is True
    assert replay["log"] == log1
    assert _log(store, gid) == log1
    assert len(service.list_packages(store, gid)[1]["packages"]) == 1


def test_race_loser_does_not_change_root(store, group):
    gid, keys = group
    results, errors = [], []

    def attempt(i):
        try:
            results.append(_submit(store, gid, keys, f"op-{i}", GENESIS, 1, f"cfg-{i}"))
        except ApiError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 1 and len(errors) == 7
    winner = results[0][1]
    # the log moved exactly once, to the winner's leaf alone
    assert _log(store, gid) == {
        "size": 1,
        "root": merkle.root_hex([merkle.leaf_hash_hex(gid, 1, winner["digest"])]),
    }
    assert winner["log"] == _log(store, gid)


def test_restart_rebuilds_same_root_and_proofs(tmp_path):
    db = str(tmp_path / "seal.db")
    s1 = Store(db)
    keys = generate_keys(3)
    service.create_group(s1, {"group_id": "g", "threshold": 2,
                              "public_keys": [k[2] for k in keys]})
    _, p1 = _submit(s1, "g", keys, "op-1", GENESIS, 1, "a")
    _, p2 = _submit(s1, "g", keys, "op-2", p1["digest"], 2, "b")
    _, p3 = _submit(s1, "g", keys, "op-3", p2["digest"], 3, "c")
    log_before = _log(s1, "g")
    _, proof_before = service.get_consistency(s1, "g", {"first": ["1"], "second": ["3"]})
    s1.close()

    # restart: root and proofs are rebuilt from confirmed packages alone
    s2 = Store(db)
    try:
        assert _log(s2, "g") == log_before
        _, proof_after = service.get_consistency(s2, "g", {"first": ["1"], "second": ["3"]})
        assert proof_after == proof_before
        # and the log keeps extending from the rebuilt root
        status, p4 = _submit(s2, "g", keys, "op-4", p3["digest"], 4, "d")
        assert status == 201
        assert p4["log"] == {"size": 4, "root": _expected_root(s2, "g")}
    finally:
        s2.close()


def _verify_hex(m, n, proof_resp):
    return merkle.verify_consistency(
        m, n,
        bytes.fromhex(proof_resp["first_root"]),
        bytes.fromhex(proof_resp["second_root"]),
        [bytes.fromhex(x) for x in proof_resp["proof"]],
    )


def test_consistency_proof_ranges(store, group):
    gid, keys = group
    # empty log: only the (0, 0) range exists
    status, pr = service.get_consistency(store, gid, {"first": ["0"], "second": ["0"]})
    assert status == 200
    assert pr["first_root"] == pr["second_root"] == merkle.EMPTY_ROOT_HEX
    assert pr["proof"] == []
    with pytest.raises(ApiError) as e:
        service.get_consistency(store, gid, {"first": ["0"], "second": ["1"]})
    assert _err(e) == (409, "size_out_of_range")

    prev = GENESIS
    for seq in range(1, 6):
        _, p = _submit(store, gid, keys, f"op-{seq}", prev, seq, f"cfg-{seq}")
        prev = p["digest"]

    # empty prefix: empty proof, first root is the empty-tree hash
    _, pr = service.get_consistency(store, gid, {"first": ["0"], "second": ["5"]})
    assert pr["proof"] == []
    assert pr["first_root"] == merkle.EMPTY_ROOT_HEX
    assert pr["second_root"] == _log(store, gid)["root"]
    assert _verify_hex(0, 5, pr)

    # full range from the first leaf
    _, pr = service.get_consistency(store, gid, {"first": ["1"], "second": ["5"]})
    assert _verify_hex(1, 5, pr)

    # non-power-of-two boundary exercises the unbalanced split
    _, pr = service.get_consistency(store, gid, {"first": ["3"], "second": ["5"]})
    assert pr["first_root"] == merkle.root_hex(
        [merkle.leaf_hash_hex(gid, p["seq"], p["digest"])
         for p in service.list_packages(store, gid)[1]["packages"][:3]]
    )
    assert _verify_hex(3, 5, pr)
    # a tampered sibling digest must fail independent verification
    bad = dict(pr, proof=[("00" if not pr["proof"][0].startswith("00") else "01")
                          + pr["proof"][0][2:], *pr["proof"][1:]])
    assert not _verify_hex(3, 5, bad)

    # equal sizes: empty proof, identical roots
    _, pr = service.get_consistency(store, gid, {"first": ["2"], "second": ["2"]})
    assert pr["proof"] == [] and pr["first_root"] == pr["second_root"]
    assert _verify_hex(2, 2, pr)


def test_consistency_proof_rejections(store, group):
    gid, keys = group
    _submit(store, gid, keys, "op-1", GENESIS, 1, "a")

    # first > second
    with pytest.raises(ApiError) as e:
        service.get_consistency(store, gid, {"first": ["2"], "second": ["1"]})
    assert _err(e) == (400, "bad_range")
    # beyond the confirmed log size
    with pytest.raises(ApiError) as e:
        service.get_consistency(store, gid, {"first": ["1"], "second": ["99"]})
    assert _err(e) == (409, "size_out_of_range")
    # malformed queries
    for query in (
        {"second": ["1"]},                            # missing first
        {"first": ["1"]},                             # missing second
        {"first": ["x"], "second": ["1"]},            # not a number
        {"first": ["-1"], "second": ["1"]},           # negative
        {"first": ["1.5"], "second": ["2"]},          # not an integer
        {"first": ["1", "1"], "second": ["1"]},       # repeated parameter
        {"first": [""], "second": ["1"]},             # blank
    ):
        with pytest.raises(ApiError) as e:
            service.get_consistency(store, gid, query)
        assert _err(e) == (400, "bad_range"), query
    # unknown group: a proof can never span groups
    with pytest.raises(ApiError) as e:
        service.get_consistency(store, "no-such-group", {"first": ["0"], "second": ["0"]})
    assert _err(e) == (404, "unknown_group")


def test_consistency_proof_is_group_scoped(store):
    keys = generate_keys(2)
    pubs = [k[2] for k in keys]
    for gid in ("g-a", "g-b"):
        status, _ = service.create_group(store, {
            "group_id": gid, "threshold": 2, "public_keys": pubs,
        })
        assert status == 201
    _, a1 = _submit(store, "g-a", keys, "op-1", GENESIS, 1, "a-1")
    _submit(store, "g-a", keys, "op-2", a1["digest"], 2, "a-2")
    _, b1 = _submit(store, "g-b", keys, "op-1", GENESIS, 1, "b-1")
    _submit(store, "g-b", keys, "op-2", b1["digest"], 2, "b-2")

    _, pra = service.get_consistency(store, "g-a", {"first": ["1"], "second": ["2"]})
    _, prb = service.get_consistency(store, "g-b", {"first": ["1"], "second": ["2"]})
    # the group id is bound into every leaf, so the histories differ
    assert pra["second_root"] != prb["second_root"]
    assert _verify_hex(1, 2, pra) and _verify_hex(1, 2, prb)
    # a proof from one group can never validate against the other's root
    crossed = dict(pra, second_root=prb["second_root"])
    assert not _verify_hex(1, 2, crossed)


# --------------------------------------------------------------------------
# HTTP smoke test through the real socket server
# --------------------------------------------------------------------------

def test_http_end_to_end(tmp_path):
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
        status, health = call("GET", "/healthz")
        assert status == 200 and health["status"] == "ok"

        keys = generate_keys(3)
        status, created = call("POST", "/v1/groups", {
            "group_id": "http-g", "threshold": 2,
            "public_keys": [k[2] for k in keys],
        })
        assert status == 201

        body = {
            "op_id": "op-1", "prev_digest": GENESIS, "seq": 1, "config": "cfg",
            "signatures": [signature_entry(keys[i][0], keys[i][1], "http-g", GENESIS, 1, "cfg")
                           for i in (0, 1)],
        }
        status, pkg = call("POST", "/v1/groups/http-g/packages", body)
        assert status == 201 and pkg["seq"] == 1

        status, replay = call("POST", "/v1/groups/http-g/packages", body)
        assert status == 200 and replay["replay"] is True

        status, info = call("GET", "/v1/groups/http-g")
        assert status == 200 and info["head"]["digest"] == pkg["digest"]

        # correctly signed but does not extend the confirmed head -> 409
        stale = {
            "op_id": "op-2", "prev_digest": pkg["digest"], "seq": 5, "config": "cfg",
            "signatures": [signature_entry(keys[i][0], keys[i][1], "http-g",
                                           pkg["digest"], 5, "cfg") for i in (0, 1)],
        }
        status, err = call("POST", "/v1/groups/http-g/packages", stale)
        assert status == 409 and err["error"] == "stale_predecessor"

        # the stale attempt did not move the Merkle log
        status, info = call("GET", "/v1/groups/http-g")
        assert status == 200 and info["log"] == pkg["log"] == {"size": 1, "root": pkg["log"]["root"]}

        # consistency proof over HTTP: empty prefix and full range
        status, pr = call("GET", "/v1/groups/http-g/log/consistency?first=0&second=1")
        assert status == 200 and pr["proof"] == []
        assert pr["first_root"] == merkle.EMPTY_ROOT_HEX
        assert pr["second_root"] == info["log"]["root"]
        status, pr = call("GET", "/v1/groups/http-g/log/consistency?first=1&second=1")
        assert status == 200 and pr["proof"] == []
        assert pr["first_root"] == pr["second_root"] == info["log"]["root"]

        # deterministic rejections over HTTP
        status, err = call("GET", "/v1/groups/http-g/log/consistency?first=2&second=1")
        assert status == 400 and err["error"] == "bad_range"
        status, err = call("GET", "/v1/groups/http-g/log/consistency?first=0&second=99")
        assert status == 409 and err["error"] == "size_out_of_range"
        status, err = call("GET", "/v1/groups/http-g/log/consistency?first=abc&second=1")
        assert status == 400 and err["error"] == "bad_range"
        status, err = call("GET", "/v1/groups/nope/log/consistency?first=0&second=0")
        assert status == 404 and err["error"] == "unknown_group"
    finally:
        httpd.shutdown()
        httpd.server_close()
        store.close()
