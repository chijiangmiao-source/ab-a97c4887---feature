"""Pure-Merkle tests: RFC 6962 hashing, consistency proofs, verification."""
from __future__ import annotations

import hashlib

import pytest

from app import merkle


def _leaves(n: int, seed: bytes = b"") -> list[bytes]:
    """Deterministic pseudo-random leaf hashes."""
    return [hashlib.sha256(seed + i.to_bytes(4, "big")).digest() for i in range(n)]


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


# --------------------------------------------------------------------------
# tree hashing
# --------------------------------------------------------------------------

def test_empty_root_is_sha256_of_empty_input():
    assert merkle.root([]) == hashlib.sha256(b"").digest()
    assert merkle.root_hex([]) == hashlib.sha256(b"").hexdigest()
    assert merkle.EMPTY_ROOT_HEX == hashlib.sha256(b"").hexdigest()


def test_leaf_hash_is_domain_separated_and_group_scoped():
    gid, seq, digest = "run-2026-09", 7, "ab" * 32
    expected_input = (
        b"LXe-ConfigSeal-Log/v1" + b"\x00"
        + len(gid.encode("utf-8")).to_bytes(2, "big") + gid.encode("utf-8")
        + seq.to_bytes(8, "big")
        + bytes.fromhex(digest)
    )
    assert merkle.leaf_hash(gid, seq, digest) == hashlib.sha256(
        b"\x00" + expected_input
    ).digest()
    # the group id is bound into every leaf: same seq+digest elsewhere differs
    assert merkle.leaf_hash("other-group", seq, digest) != merkle.leaf_hash(gid, seq, digest)
    # and the leaf domain differs from the signature domain of crypto.py
    assert not expected_input.startswith(b"LXe-ConfigSeal/v1")


def test_single_leaf_root_is_the_leaf_hash():
    (l0,) = _leaves(1)
    assert merkle.root([l0]) == l0


def test_unbalanced_roots():
    l0, l1, l2, l3, l4 = _leaves(5)
    assert merkle.root([l0, l1]) == _node(l0, l1)
    # n=3 splits k=2 / 1; n=5 splits k=4 / 1 (largest power of two < n)
    assert merkle.root([l0, l1, l2]) == _node(_node(l0, l1), l2)
    assert merkle.root([l0, l1, l2, l3, l4]) == _node(
        _node(_node(l0, l1), _node(l2, l3)), l4
    )


# --------------------------------------------------------------------------
# proof generation: pinned vectors for the unbalanced split rule
# --------------------------------------------------------------------------

def test_proof_vectors():
    leaves = _leaves(5)
    l0, l1, l2, l3, l4 = leaves
    assert merkle.consistency_proof(1, leaves[:1]) == []
    assert merkle.consistency_proof(1, leaves[:2]) == [l1]
    assert merkle.consistency_proof(2, leaves[:3]) == [l2]
    # m=3, n=5: SUBPROOF(3, D5) = [l2, l3, H(l0||l1), l4]
    assert merkle.consistency_proof(3, leaves) == [l2, l3, _node(l0, l1), l4]
    # m=4, n=5: the first four leaves are a complete subtree
    assert merkle.consistency_proof(4, leaves) == [l4]


def test_proof_requires_valid_range():
    with pytest.raises(ValueError):
        merkle.consistency_proof(0, _leaves(1))
    with pytest.raises(ValueError):
        merkle.consistency_proof(3, _leaves(2))


# --------------------------------------------------------------------------
# generate -> verify round trips and tamper rejection
# --------------------------------------------------------------------------

def test_proof_roundtrip_all_pairs_up_to_40():
    for n in range(1, 41):
        leaves = _leaves(n, seed=b"roundtrip")
        root_n = merkle.root(leaves)
        for m in range(1, n + 1):
            root_m = merkle.root(leaves[:m])
            proof = merkle.consistency_proof(m, leaves)
            assert merkle.verify_consistency(m, n, root_m, root_n, proof), (m, n)
            # the proof is minimal: never more than ceil(log2(n)) + 1 nodes
            assert len(proof) <= n.bit_length() + 1
        # empty prefix: empty proof against the fixed empty-tree root
        assert merkle.verify_consistency(0, n, merkle.EMPTY_ROOT, root_n, [])
        # equal sizes: empty proof, equal roots
        assert merkle.verify_consistency(n, n, root_n, root_n, [])


def test_verify_rejects_tampered_proofs_and_roots():
    leaves = _leaves(9, seed=b"tamper")
    n = len(leaves)
    root_n = merkle.root(leaves)
    for m in (1, 2, 3, 4, 5, 7, 8):
        root_m = merkle.root(leaves[:m])
        proof = merkle.consistency_proof(m, leaves)
        # flipping one bit in any sibling digest breaks the proof
        for i in range(len(proof)):
            bad = list(proof)
            bad[i] = bytes([bad[i][0] ^ 1]) + bad[i][1:]
            assert not merkle.verify_consistency(m, n, root_m, root_n, bad)
        # either root replaced by the other (or by garbage) fails
        assert not merkle.verify_consistency(m, n, root_n, root_n, proof)
        assert not merkle.verify_consistency(m, n, root_m, root_m, proof)
        assert not merkle.verify_consistency(m, n, b"\x00" * 32, root_n, proof)
        # truncated, extended or reordered proofs fail
        if proof:
            assert not merkle.verify_consistency(m, n, root_m, root_n, proof[:-1])
        assert not merkle.verify_consistency(m, n, root_m, root_n, proof + [leaves[0]])
        if len(proof) > 1:
            swapped = [proof[1], proof[0], *proof[2:]]
            assert not merkle.verify_consistency(m, n, root_m, root_n, swapped)
        # swapped sizes are nonsense
        assert not merkle.verify_consistency(n, m, root_m, root_n, proof)


def test_verify_degenerate_inputs():
    (l0,) = _leaves(1)
    root1 = merkle.root([l0])
    # m == 0 requires the fixed empty root and an empty proof
    assert not merkle.verify_consistency(0, 1, root1, root1, [])
    assert not merkle.verify_consistency(0, 1, merkle.EMPTY_ROOT, root1, [l0])
    # m == n requires equal roots and an empty proof
    assert not merkle.verify_consistency(1, 1, root1, root1, [l0])
    assert not merkle.verify_consistency(1, 1, root1, merkle.EMPTY_ROOT, [])
    # malformed sizes / digests
    assert not merkle.verify_consistency(-1, 1, merkle.EMPTY_ROOT, root1, [])
    assert not merkle.verify_consistency(1, 1, b"short", root1, [])
    assert not merkle.verify_consistency(1, 2, root1, root1, [b"short"])
