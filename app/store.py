"""SQLite persistence for the threshold-sealed config chain.

All state-changing work for a submission happens inside ONE ``BEGIN
IMMEDIATE`` transaction: idempotency-receipt lookup, chain-head check,
package insert, receipt insert and head move. Competing writers are
serialised by the database write lock, so at most one request can ever
extend a given predecessor.
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
-- Per-group append-only Merkle log (RFC 9162): one leaf per confirmed
-- package. Leaves and the cumulative root are written in the SAME commit
-- as the package/receipt/head, so the log can never disagree with the
-- confirmed history.
CREATE TABLE IF NOT EXISTS log_leaves (
    group_id  TEXT NOT NULL REFERENCES groups(group_id),
    log_seq   INTEGER NOT NULL,          -- 1-based position in the log
    pkg_seq   INTEGER NOT NULL,
    leaf_hash TEXT NOT NULL,             -- RFC 9162 leaf hash (hex)
    PRIMARY KEY (group_id, log_seq),
    UNIQUE (group_id, pkg_seq)
);
CREATE TABLE IF NOT EXISTS log_state (
    group_id  TEXT PRIMARY KEY REFERENCES groups(group_id),
    log_size  INTEGER NOT NULL,          -- number of leaves
    root_hash TEXT NOT NULL              -- MTH over all leaves (hex)
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
            self._rebuild_logs()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- recovery ---------------------------------------------------------
    def _rebuild_heads(self) -> None:
        """Derive every group's unique chain head from confirmed packages.

        Runs on every startup: after a restart the chain head is recovered
        from the durable package records, never from stale side state.
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
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    def _rebuild_logs(self) -> None:
        """Rebuild every group's Merkle log solely from confirmed packages.

        After a restart the leaf list and the cumulative root are
        recomputed from the durable ``packages`` rows (ordered by seq), so
        the recovered root and every consistency proof are byte-identical
        to the ones served before the restart.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            group_ids = [
                r["group_id"] for r in self._conn.execute("SELECT group_id FROM groups")
            ]
            for gid in group_ids:
                rows = self._conn.execute(
                    "SELECT seq, digest, op_id FROM packages"
                    " WHERE group_id=? ORDER BY seq",
                    (gid,),
                ).fetchall()
                self._conn.execute(
                    "DELETE FROM log_leaves WHERE group_id=?", (gid,)
                )
                leaves: list[bytes] = []
                for i, row in enumerate(rows, start=1):
                    lh = merkle.leaf_hash(gid, row["seq"], row["digest"])
                    leaves.append(bytes.fromhex(lh))
                    self._conn.execute(
                        "INSERT INTO log_leaves (group_id, log_seq, pkg_seq, leaf_hash)"
                        " VALUES (?,?,?,?)",
                        (gid, i, row["seq"], lh),
                    )
                    # Backfill receipts written before the log existed: attach
                    # the immutable as-of-commit snapshot they correspond to.
                    receipt = self._conn.execute(
                        "SELECT response_json FROM receipts"
                        " WHERE group_id=? AND op_id=?",
                        (gid, row["op_id"]),
                    ).fetchone()
                    if receipt is not None:
                        payload = json.loads(receipt["response_json"])
                        if "log" not in payload:
                            payload["log"] = {"size": i, "root_hash": merkle.root(leaves).hex()}
                            self._conn.execute(
                                "UPDATE receipts SET response_json=? WHERE group_id=? AND op_id=?",
                                (json.dumps(payload), gid, row["op_id"]),
                            )
                root_hash = merkle.root(leaves).hex()
                self._conn.execute(
                    "INSERT INTO log_state (group_id, log_size, root_hash) VALUES (?,?,?)"
                    " ON CONFLICT(group_id) DO UPDATE SET"
                    " log_size=excluded.log_size, root_hash=excluded.root_hash",
                    (gid, len(rows), root_hash),
                )
                if rows:
                    log.info(
                        "recovered merkle log: group=%s size=%d root=%s…",
                        gid, len(rows), root_hash[:16],
                    )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

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
                self._conn.execute(
                    "INSERT INTO log_state (group_id, log_size, root_hash) VALUES (?,?,?)",
                    (group_id, 0, merkle.EMPTY_ROOT_HASH),
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

    # -- Merkle log ----------------------------------------------------------
    def get_log_state(self, group_id: str) -> tuple[int, str] | None:
        """Current (size, root_hash) of the group's Merkle log; None if unknown."""
        with self._lock:
            row = self._conn.execute(
                "SELECT log_size, root_hash FROM log_state WHERE group_id=?",
                (group_id,),
            ).fetchone()
            return (row["log_size"], row["root_hash"]) if row else None

    def _log_leaves_locked(self, group_id: str) -> list[bytes]:
        rows = self._conn.execute(
            "SELECT leaf_hash FROM log_leaves WHERE group_id=? ORDER BY log_seq",
            (group_id,),
        ).fetchall()
        return [bytes.fromhex(r["leaf_hash"]) for r in rows]

    def get_consistency(
        self, group_id: str, first: int, second: int
    ) -> tuple[str, str, list[str]]:
        """Return (first_root, second_root, proof_hashes) for sizes first<=second.

        Reads are served inside the same serialising lock as commits, so
        the roots and proof always describe one coherent prefix of the log.
        """
        with self._lock:
            state = self._conn.execute(
                "SELECT log_size FROM log_state WHERE group_id=?", (group_id,)
            ).fetchone()
            if state is None:
                raise KeyError(group_id)
            if not (0 <= first <= second <= state["log_size"]):
                raise ValueError((first, second, state["log_size"]))
            leaves = self._log_leaves_locked(group_id)
            first_root = merkle.root(leaves[:first]).hex()
            second_root = merkle.root(leaves[:second]).hex()
            proof = [
                h.hex() for h in merkle.consistency_proof(leaves[:second], first, second)
            ]
            return first_root, second_root, proof

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
        receipt, verify the current head, write the package, write the
        idempotency receipt and move the head. Returns (response, replayed).
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
                        # Append the domain-separated Merkle leaf and save
                        # the recomputable cumulative root in THIS commit, so
                        # package/receipt/head/log always move together.
                        lh = merkle.leaf_hash(group_id, seq, digest)
                        size_row = self._conn.execute(
                            "SELECT log_size FROM log_state WHERE group_id=?",
                            (group_id,),
                        ).fetchone()
                        new_size = size_row["log_size"] + 1
                        self._conn.execute(
                            "INSERT INTO log_leaves (group_id, log_seq, pkg_seq, leaf_hash)"
                            " VALUES (?,?,?,?)",
                            (group_id, new_size, seq, lh),
                        )
                        leaves = self._log_leaves_locked(group_id)
                        new_root = merkle.root(leaves).hex()
                        self._conn.execute(
                            "UPDATE log_state SET log_size=?, root_hash=? WHERE group_id=?",
                            (new_size, new_root, group_id),
                        )
                        # Persist the log snapshot AS OF this confirmation
                        # inside the receipt: it is immutable, so an
                        # idempotent replay (even after later packages)
                        # returns the same size/root byte-for-byte.
                        response = dict(
                            response,
                            log={"size": new_size, "root_hash": new_root},
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
