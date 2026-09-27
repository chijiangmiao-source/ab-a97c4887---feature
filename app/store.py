"""SQLite persistence for the threshold-sealed config chain.

All state-changing work for a submission happens inside ONE ``BEGIN
IMMEDIATE`` transaction: idempotency-receipt lookup, chain-head check,
package insert, Merkle leaf append + cumulative root save, receipt
insert and head move. Competing writers are serialised by the database
write lock, so at most one request can ever extend a given predecessor.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone

from . import merkle
from .crypto import GENESIS_DIGEST

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS groups (
    group_id   TEXT PRIMARY KEY,
    threshold  INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_keys (
    group_id   TEXT NOT NULL REFERENCES groups(group_id),
    key_id     TEXT NOT NULL,
    pubkey_hex TEXT NOT NULL,
    PRIMARY KEY (group_id, key_id)
);
CREATE TABLE IF NOT EXISTS packages (
    group_id    TEXT NOT NULL REFERENCES groups(group_id),
    seq         INTEGER NOT NULL,
    digest      TEXT NOT NULL,
    prev_digest TEXT NOT NULL,
    op_id       TEXT NOT NULL,
    config      TEXT NOT NULL,
    signers     TEXT NOT NULL,          -- JSON array of signer key ids
    created_at  TEXT NOT NULL,
    PRIMARY KEY (group_id, seq),
    UNIQUE (group_id, digest)
);
CREATE TABLE IF NOT EXISTS receipts (
    group_id      TEXT NOT NULL REFERENCES groups(group_id),
    op_id         TEXT NOT NULL,
    request_hash  TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (group_id, op_id)
);
CREATE TABLE IF NOT EXISTS heads (
    group_id    TEXT PRIMARY KEY REFERENCES groups(group_id),
    head_seq    INTEGER NOT NULL,
    head_digest TEXT NOT NULL
);
-- Append-only Merkle log over confirmed packages (RFC 6962). Leaf index
-- is seq - 1: the log and the chain are the same linear history. Both
-- tables are derived state — they are rebuilt from `packages` on every
-- startup and appended to only inside the confirmation transaction.
CREATE TABLE IF NOT EXISTS merkle_leaves (
    group_id   TEXT NOT NULL REFERENCES groups(group_id),
    leaf_index INTEGER NOT NULL,
    seq        INTEGER NOT NULL,
    leaf_hash  TEXT NOT NULL,       -- hex of SHA-256(0x00 || leaf_input)
    PRIMARY KEY (group_id, leaf_index),
    UNIQUE (group_id, seq)
);
CREATE TABLE IF NOT EXISTS merkle_roots (
    group_id  TEXT NOT NULL REFERENCES groups(group_id),
    tree_size INTEGER NOT NULL,     -- cumulative root after this many leaves
    root      TEXT NOT NULL,        -- hex, recomputable from merkle_leaves
    PRIMARY KEY (group_id, tree_size)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class OpIdConflict(Exception):
    """The op_id was already confirmed with a different payload."""


class StalePredecessor(Exception):
    """prev_digest/seq do not extend the currently confirmed head."""


class RaceLost(Exception):
    """The head moved while this request was committing."""


class Store:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._rebuild_heads()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- recovery ---------------------------------------------------------
    def _rebuild_heads(self) -> None:
        """Derive every group's head and Merkle log from confirmed packages.

        Runs on every startup: after a restart the chain head and the
        Merkle log are recovered from the durable package records, never
        from stale side state, so the rebuilt cumulative root and any
        consistency proof are bit-identical to the pre-restart ones.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            group_ids = [
                r["group_id"] for r in self._conn.execute("SELECT group_id FROM groups")
            ]
            for gid in group_ids:
                row = self._conn.execute(
                    "SELECT seq, digest FROM packages WHERE group_id=?"
                    " ORDER BY seq DESC LIMIT 1",
                    (gid,),
                ).fetchone()
                seq, digest = (row["seq"], row["digest"]) if row else (0, GENESIS_DIGEST)
                self._conn.execute(
                    "INSERT INTO heads (group_id, head_seq, head_digest) VALUES (?,?,?)"
                    " ON CONFLICT(group_id) DO UPDATE SET"
                    " head_seq=excluded.head_seq, head_digest=excluded.head_digest",
                    (gid, seq, digest),
                )
                if row:
                    log.info(
                        "recovered chain head: group=%s seq=%d digest=%s…",
                        gid, seq, digest[:16],
                    )
                self._rebuild_merkle(gid)
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    def _rebuild_merkle(self, group_id: str) -> None:
        """Re-derive the group's Merkle leaves and cumulative roots.

        ``packages`` is the source of truth; the leaf input is a pure
        function of (group_id, seq, digest), so replaying the confirmed
        chain always reproduces the same leaves, roots and proofs.
        """
        rows = self._conn.execute(
            "SELECT seq, digest FROM packages WHERE group_id=? ORDER BY seq",
            (group_id,),
        ).fetchall()
        self._conn.execute("DELETE FROM merkle_leaves WHERE group_id=?", (group_id,))
        self._conn.execute("DELETE FROM merkle_roots WHERE group_id=?", (group_id,))
        hashes: list[str] = []
        for row in rows:
            hashes.append(merkle.leaf_hash_hex(group_id, row["seq"], row["digest"]))
            self._conn.execute(
                "INSERT INTO merkle_leaves (group_id, leaf_index, seq, leaf_hash)"
                " VALUES (?,?,?,?)",
                (group_id, row["seq"] - 1, row["seq"], hashes[-1]),
            )
            # Chain sizes here are small (one leaf per confirmed config
            # package), so recomputing the cumulative root from the leaf
            # prefix is cheap and keeps the stored root honest by
            # construction.
            self._conn.execute(
                "INSERT INTO merkle_roots (group_id, tree_size, root) VALUES (?,?,?)",
                (group_id, row["seq"], merkle.root_hex(hashes)),
            )
        if hashes:
            log.info(
                "recovered merkle root: group=%s size=%d root=%s…",
                group_id, len(hashes), merkle.root_hex(hashes)[:16],
            )

    # -- groups -------------------------------------------------------------
    def create_group(self, group_id: str, threshold: int, keys: list[tuple[str, str]]) -> bool:
        """Register a seal group. Returns False if the group id already exists."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if self._conn.execute(
                    "SELECT 1 FROM groups WHERE group_id=?", (group_id,)
                ).fetchone():
                    self._conn.execute("ROLLBACK")
                    return False
                self._conn.execute(
                    "INSERT INTO groups (group_id, threshold, created_at) VALUES (?,?,?)",
                    (group_id, threshold, _now()),
                )
                self._conn.executemany(
                    "INSERT INTO group_keys (group_id, key_id, pubkey_hex) VALUES (?,?,?)",
                    [(group_id, kid, hex_) for kid, hex_ in keys],
                )
                self._conn.execute(
                    "INSERT INTO heads (group_id, head_seq, head_digest) VALUES (?,?,?)",
                    (group_id, 0, GENESIS_DIGEST),
                )
                self._conn.execute("COMMIT")
                return True
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def get_group(self, group_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT group_id, threshold, created_at FROM groups WHERE group_id=?",
                (group_id,),
            ).fetchone()
            if row is None:
                return None
            keys = {
                r["key_id"]: r["pubkey_hex"]
                for r in self._conn.execute(
                    "SELECT key_id, pubkey_hex FROM group_keys WHERE group_id=?",
                    (group_id,),
                )
            }
            return {
                "group_id": row["group_id"],
                "threshold": row["threshold"],
                "created_at": row["created_at"],
                "keys": keys,
            }

    def get_head(self, group_id: str) -> tuple[int, str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT head_seq, head_digest FROM heads WHERE group_id=?", (group_id,)
            ).fetchone()
            return (row["head_seq"], row["head_digest"]) if row else None

    def list_packages(self, group_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, digest, prev_digest, op_id, config, signers, created_at"
                " FROM packages WHERE group_id=? ORDER BY seq",
                (group_id,),
            ).fetchall()
            return [
                {
                    "seq": r["seq"],
                    "digest": r["digest"],
                    "prev_digest": r["prev_digest"],
                    "op_id": r["op_id"],
                    "config": r["config"],
                    "signers": json.loads(r["signers"]),
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

    # -- Merkle log reads ---------------------------------------------------
    def get_log_state(self, group_id: str) -> tuple[int, str]:
        """Current (size, cumulative root hex) of the group's Merkle log."""
        with self._lock:
            row = self._conn.execute(
                "SELECT tree_size, root FROM merkle_roots WHERE group_id=?"
                " ORDER BY tree_size DESC LIMIT 1",
                (group_id,),
            ).fetchone()
            if row is None:
                return 0, merkle.EMPTY_ROOT_HEX
            return row["tree_size"], row["root"]

    def get_leaf_hashes(self, group_id: str, limit: int) -> list[str]:
        """First ``limit`` leaf hashes (hex), in log order."""
        with self._lock:
            return [
                r["leaf_hash"]
                for r in self._conn.execute(
                    "SELECT leaf_hash FROM merkle_leaves WHERE group_id=?"
                    " ORDER BY leaf_index LIMIT ?",
                    (group_id, limit),
                )
            ]

    # -- package submission -------------------------------------------------
    def submit_package(
        self,
        *,
        group_id: str,
        op_id: str,
        prev_digest: str,
        seq: int,
        config: str,
        digest: str,
        signer_ids: list[str],
        request_hash: str,
        response: dict,
    ) -> tuple[dict, bool]:
        """Confirm a package atomically.

        Inside a single persistent transaction: honour a prior idempotent
        receipt, verify the current head, write the package, append the
        Merkle leaf and save the cumulative root, write the idempotency
        receipt and move the head. Returns (response, replayed); the
        response carries the resulting log size and root.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                outcome: tuple
                receipt = self._conn.execute(
                    "SELECT request_hash, response_json FROM receipts"
                    " WHERE group_id=? AND op_id=?",
                    (group_id, op_id),
                ).fetchone()
                if receipt is not None:
                    outcome = ("receipt", receipt)
                else:
                    head = self._conn.execute(
                        "SELECT head_seq, head_digest FROM heads WHERE group_id=?",
                        (group_id,),
                    ).fetchone()
                    if head is None or (
                        prev_digest != head["head_digest"]
                        or seq != head["head_seq"] + 1
                    ):
                        outcome = ("stale",)
                    else:
                        moved = self._conn.execute(
                            "UPDATE heads SET head_seq=?, head_digest=?"
                            " WHERE group_id=? AND head_seq=? AND head_digest=?",
                            (seq, digest, group_id, head["head_seq"], head["head_digest"]),
                        )
                        if moved.rowcount != 1:
                            raise RaceLost()
                        self._conn.execute(
                            "INSERT INTO packages (group_id, seq, digest, prev_digest,"
                            " op_id, config, signers, created_at)"
                            " VALUES (?,?,?,?,?,?,?,?)",
                            (
                                group_id, seq, digest, prev_digest, op_id, config,
                                json.dumps(signer_ids), _now(),
                            ),
                        )
                        # Merkle append in the SAME commit: leaf for
                        # (group_id, seq, digest) plus the cumulative root.
                        # A replayed, rejected or racing submission never
                        # reaches this point, so it can never move the root.
                        self._conn.execute(
                            "INSERT INTO merkle_leaves"
                            " (group_id, leaf_index, seq, leaf_hash) VALUES (?,?,?,?)",
                            (
                                group_id, seq - 1, seq,
                                merkle.leaf_hash_hex(group_id, seq, digest),
                            ),
                        )
                        hashes = [
                            r["leaf_hash"]
                            for r in self._conn.execute(
                                "SELECT leaf_hash FROM merkle_leaves WHERE group_id=?"
                                " ORDER BY leaf_index",
                                (group_id,),
                            )
                        ]
                        log_root = merkle.root_hex(hashes)
                        self._conn.execute(
                            "INSERT INTO merkle_roots (group_id, tree_size, root)"
                            " VALUES (?,?,?)",
                            (group_id, seq, log_root),
                        )
                        response = dict(
                            response, log={"size": seq, "root": log_root}
                        )
                        self._conn.execute(
                            "INSERT INTO receipts (group_id, op_id, request_hash,"
                            " response_json, created_at) VALUES (?,?,?,?,?)",
                            (group_id, op_id, request_hash, json.dumps(response), _now()),
                        )
                        outcome = ("ok", response)
                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise RaceLost() from exc
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

        if outcome[0] == "receipt":
            receipt = outcome[1]
            if receipt["request_hash"] != request_hash:
                raise OpIdConflict(op_id)
            return json.loads(receipt["response_json"]), True
        if outcome[0] == "stale":
            raise StalePredecessor()
        return outcome[1], False
