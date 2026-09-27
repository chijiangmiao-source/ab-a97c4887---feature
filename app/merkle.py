"""RFC 6962 Merkle tree over the confirmed package chain.

Every confirmed package becomes exactly one log leaf, in chain order
(leaf index == seq - 1). The leaf input is domain-separated and commits
to the group id, the seq and the package digest, so a leaf can never be
reinterpreted across groups or protocol versions:

    DOMAIN_SEPARATOR("LXe-ConfigSeal-Log/v1") || 0x00
    || uint16BE(len(group_id)) || group_id          (UTF-8)
    || uint64BE(seq)
    || digest                                       (32 raw bytes)

Hashing follows RFC 6962 §2.1: a leaf is SHA-256(0x00 || leaf_input),
an interior node is SHA-256(0x01 || left || right), and the empty tree
root is SHA-256(""). Consistency proofs use the RFC's unbalanced-split
SUBPROOF rule, so an independent verifier can decide whether the root
at size ``first`` commits to a prefix of the history behind the root at
size ``second`` — knowing only the two sizes, the two roots and the
proof's sibling digests, never the intermediate config texts.
"""
from __future__ import annotations

import hashlib

# Domain separator for log leaves: distinct from the signature domain in
# crypto.py, so a package signature can never be repurposed as a leaf.
LEAF_DOMAIN = b"LXe-ConfigSeal-Log/v1"

_LEAF_PREFIX = b"\x00"  # RFC 6962 §2.1 leaf prefix
_NODE_PREFIX = b"\x01"  # RFC 6962 §2.1 interior-node prefix

HASH_LEN = 32

# Root of the empty tree: SHA-256 of the empty input (RFC 6962 §2.1).
EMPTY_ROOT = hashlib.sha256(b"").digest()
EMPTY_ROOT_HEX = EMPTY_ROOT.hex()


def leaf_input(group_id: str, seq: int, digest_hex: str) -> bytes:
    """Canonical byte sequence committed to by one log leaf."""
    gid = group_id.encode("utf-8")
    return (
        LEAF_DOMAIN
        + b"\x00"
        + len(gid).to_bytes(2, "big")
        + gid
        + seq.to_bytes(8, "big")
        + bytes.fromhex(digest_hex)
    )


def leaf_hash(group_id: str, seq: int, digest_hex: str) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || leaf_input)."""
    return hashlib.sha256(_LEAF_PREFIX + leaf_input(group_id, seq, digest_hex)).digest()


def leaf_hash_hex(group_id: str, seq: int, digest_hex: str) -> str:
    return leaf_hash(group_id, seq, digest_hex).hex()


def hash_children(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _largest_pow2_below(n: int) -> int:
    """Largest power of two strictly smaller than n (requires n >= 2)."""
    return n >> 1 if n & (n - 1) == 0 else 1 << (n.bit_length() - 1)


def root(leaf_hashes: list[bytes]) -> bytes:
    """Merkle Tree Hash (RFC 6962 §2.1) over already-hashed leaves."""
    n = len(leaf_hashes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaf_hashes[0]
    k = _largest_pow2_below(n)
    return hash_children(root(leaf_hashes[:k]), root(leaf_hashes[k:]))


def root_hex(leaf_hashes_hex: list[str]) -> str:
    return root([bytes.fromhex(h) for h in leaf_hashes_hex]).hex()


def consistency_proof(m: int, leaf_hashes: list[bytes]) -> list[bytes]:
    """PROOF(m, D_n) of RFC 6962 §2.1.2, where n = len(leaf_hashes).

    Returns the minimal set of sibling node hashes, in the canonical
    bottom-up order produced by the unbalanced-split recursion.
    Requires 0 < m <= n; the callers handle m == 0 (empty proof, the
    empty tree is a prefix of every tree) and m == n (empty proof).
    """
    if not 0 < m <= len(leaf_hashes):
        raise ValueError("consistency proof requires 0 < m <= n")
    return _subproof(m, leaf_hashes, True)


def _subproof(m: int, d: list[bytes], complete: bool) -> list[bytes]:
    """SUBPROOF(m, D, b): b is True iff m is a complete subtree of D."""
    if m == len(d):
        return [] if complete else [root(d)]
    k = _largest_pow2_below(len(d))
    if m <= k:
        # Right subtree exists only in the later tree.
        return _subproof(m, d[:k], complete) + [root(d[k:])]
    # Left subtree is identical in both trees.
    return _subproof(m - k, d[k:], False) + [root(d[:k])]


def verify_consistency(
    m: int,
    n: int,
    first_root: bytes,
    second_root: bytes,
    proof: list[bytes],
) -> bool:
    """Independently verify that root(m) is a prefix commitment of root(n).

    Implements the verification procedure of RFC 9162 §2.1.4.2 (the
    successor of RFC 6962): recompute both candidate roots from the
    proof's sibling digests and accept only if they match the roots the
    verifier already holds. Pure function of (m, n, roots, proof) — no
    leaf data or config text is needed.
    """
    if not isinstance(m, int) or not isinstance(n, int) or m < 0 or n < 0 or m > n:
        return False
    if len(first_root) != HASH_LEN or len(second_root) != HASH_LEN:
        return False
    if any(len(p) != HASH_LEN for p in proof):
        return False
    if m == 0:
        # The empty tree is a prefix of every tree; its root is fixed.
        return proof == [] and first_root == EMPTY_ROOT
    if m == n:
        return proof == [] and first_root == second_root
    # When m is an exact power of two, the first root is itself the
    # first proof node (RFC 9162 §2.1.4.2 step 2).
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
            fr = hash_children(c, fr)
            sr = hash_children(c, sr)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = hash_children(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root
