"""RFC 9162 ("Certificate Transparency", bis of RFC 6962) Merkle log.

One append-only Merkle log exists *per seal group*. A leaf commits to a
confirmed package using only data that is handed to downstream consumers
(group id, sequence number and the confirmed package digest) -- never the
configuration text:

    LEAF_DOMAIN_SEPARATOR("LXe-ConfigSeal-MerkleLog/v1") || 0x00
    || uint16BE(len(group_id)) || group_id      (UTF-8)
    || uint64BE(seq)
    || package_digest                            (32 raw bytes)

The log leaf hash then follows RFC 9162 section 2.1:

    HASH(0x00 || leaf_input)

and interior nodes are ``HASH(0x01 || left || right)``; the empty-tree root
is ``HASH()``. The group id inside every leaf input domain-separates the
logs of different groups, so a proof from one group can never verify
against another group's root.

Consistency proofs are the unique minimal sibling lists of RFC 9162
section 2.1.4.1, in canonical order; :func:`verify_consistency` is the
section 2.1.4.2 verification algorithm written out verbatim.
"""
from __future__ import annotations

import hashlib

LEAF_DOMAIN_SEPARATOR = b"LXe-ConfigSeal-MerkleLog/v1"

# RFC 9162: MTH({}) = HASH()
EMPTY_ROOT_HASH = hashlib.sha256(b"").hexdigest()

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_DIGEST_LEN = 32


class MerkleError(ValueError):
    """Leaf/proof material is malformed."""


def _hash(parts: bytes) -> bytes:
    return hashlib.sha256(parts).digest()


def leaf_input(group_id: str, seq: int, digest_hex: str) -> bytes:
    """Canonical byte string a Merkle log leaf commits to."""
    gid = group_id.encode("utf-8")
    if not gid or len(gid) > 0xFFFF:
        raise MerkleError("group_id must be 1..65535 UTF-8 bytes")
    if not isinstance(seq, int) or isinstance(seq, bool) or not 0 < seq < 1 << 63:
        raise MerkleError("seq must be an integer in 1..2^63-1")
    try:
        digest = bytes.fromhex(digest_hex)
    except ValueError as exc:
        raise MerkleError("digest must be hex") from exc
    if len(digest) != _DIGEST_LEN:
        raise MerkleError("digest must be 32 bytes (64 hex chars)")
    return (
        LEAF_DOMAIN_SEPARATOR
        + b"\x00"
        + len(gid).to_bytes(2, "big")
        + gid
        + seq.to_bytes(8, "big")
        + digest
    )


def leaf_hash(group_id: str, seq: int, digest_hex: str) -> str:
    """Hex Merkle leaf hash for a confirmed package."""
    return _hash(_LEAF_PREFIX + leaf_input(group_id, seq, digest_hex)).hex()


def _node(left: bytes, right: bytes) -> bytes:
    return _hash(_NODE_PREFIX + left + right)


def _largest_pow2_below(n: int) -> int:
    """Largest power of two strictly smaller than n (RFC 9162 split point)."""
    return 1 << ((n - 1).bit_length() - 1)


def _root(leaves: list[bytes], lo: int, n: int, memo: dict[tuple[int, int], bytes]) -> bytes:
    """MTH over leaves[lo:lo+n] (RFC 9162 section 2.1.1)."""
    if n == 1:
        return leaves[lo]
    cached = memo.get((lo, n))
    if cached is not None:
        return cached
    k = _largest_pow2_below(n)
    value = _node(_root(leaves, lo, k, memo), _root(leaves, lo + k, n - k, memo))
    memo[(lo, n)] = value
    return value


def root(leaves: list[bytes]) -> bytes:
    """Cumulative Merkle Tree Hash; MTH({}) = HASH() for the empty log."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    return _root(leaves, 0, len(leaves), {})


def root_from_hex(leaf_hashes: list[str]) -> str:
    return root([bytes.fromhex(h) for h in leaf_hashes]).hex()


def _subproof(
    leaves: list[bytes], m: int, lo: int, n: int, known: bool,
    memo: dict[tuple[int, int], bytes],
) -> list[bytes]:
    """SUBPROOF from RFC 9162 section 2.1.4.1, verbatim."""
    if m == n:
        return [] if known else [_root(leaves, lo, n, memo)]
    k = _largest_pow2_below(n)
    if m <= k:
        return _subproof(leaves, m, lo, k, known, memo) + [
            _root(leaves, lo + k, n - k, memo)
        ]
    return _subproof(leaves, m - k, lo + k, n - k, False, memo) + [
        _root(leaves, lo, k, memo)
    ]


def consistency_proof(leaves: list[bytes], first: int, second: int) -> list[bytes]:
    """Minimal canonical-order sibling hashes proving prefix ``first`` in ``second``.

    ``0 <= first <= second == len(leaves)``. The empty prefix and the
    equal-size degenerate case both have an empty proof path.
    """
    n = len(leaves)
    if not (0 <= first <= second == n):
        raise MerkleError(f"require 0 <= first <= second == {n}, got {first}->{second}")
    if first == 0 or first == second:
        return []
    return _subproof(leaves, first, 0, n, True, {})


def verify_consistency(
    first: int,
    second: int,
    first_hash: bytes,
    second_hash: bytes,
    path: list[bytes],
) -> bool:
    """RFC 9162 section 2.1.4.2, with the two deterministic edge cases:

    * ``first == 0`` (empty prefix): the path must be empty; the empty
      prefix is trivially contained in any later tree.
    * ``first == second``: the path must be empty and the roots must agree.
    """
    if not (0 <= first <= second):
        return False
    if first == second:
        return not path and first_hash == second_hash
    if first == 0:
        return not path
    if not path:
        return False

    proof = list(path)
    if first & (first - 1) == 0:  # first is an exact power of two
        # Step 2: prepend the previously advertised root to the path.
        proof = [first_hash] + proof

    fn, sn = first - 1, second - 1
    # Step 4: shift off trailing set bits of fn (and sn in lockstep).
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:  # step 6a: more path than tree levels
            return False
        if (fn & 1) or fn == sn:
            fr = _node(c, fr)
            sr = _node(c, sr)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1

    return fr == first_hash and sr == second_hash and sn == 0
