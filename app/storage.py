"""SQLite persistence.

Each role has its own database file. A publish/sync is committed as one
transaction: the new immutable version row and the pointer to the active
serial move together, so an answer can never be assembled from two
versions. A stale transfer (serial <= active serial) is rejected, which
guarantees a late/old transfer can never roll back an already active
version.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .config import settings

_UTC = timezone.utc
_init_lock = threading.Lock()


def utcnow_iso() -> str:
    return datetime.now(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _connect(db_path: str, timeout: float = 30) -> sqlite3.Connection:
    directory = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=timeout, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


class Storage:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        with _init_lock:
            self._init_schema()

    # -- schema ---------------------------------------------------------
    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS zone_versions (
                    serial       INTEGER PRIMARY KEY,
                    records_json TEXT    NOT NULL,
                    record_count INTEGER NOT NULL,
                    published_at TEXT    NOT NULL
                );
                CREATE TABLE IF NOT EXISTS state (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            row = conn.execute(
                "SELECT value FROM state WHERE key='active_serial'"
            ).fetchone()
            if row is None:
                # Empty seed version: the service answers NXDOMAIN but is
                # internally consistent (one active version) before publish.
                conn.execute(
                    "INSERT OR IGNORE INTO zone_versions "
                    "(serial, records_json, record_count, published_at) "
                    "VALUES (0, '[]', 0, ?)",
                    (utcnow_iso(),),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO state(key, value) "
                    "VALUES ('active_serial', '0')"
                )
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        return _connect(self.db_path)

    def _connect_read(self) -> sqlite3.Connection:
        """Short-timeout connection for the UDP hot path.

        If the zone DB is briefly locked we fail fast and the resolver
        falls back to its last known snapshot instead of stalling queries.
        """
        return _connect(self.db_path, timeout=2)

    # -- reads ----------------------------------------------------------
    @staticmethod
    def _get_state(conn: sqlite3.Connection, key: str) -> Optional[str]:
        row = conn.execute(
            "SELECT value FROM state WHERE key=?", (key,)
        ).fetchone()
        return None if row is None else row["value"]

    def get_active_version(
        self, fast: bool = False
    ) -> Tuple[int, List[Dict[str, str]], Optional[str]]:
        """Return (serial, records, published_at) of one active version.

        The pointer and the version row are read in one deferred read
        transaction so both belong to the same committed snapshot.  The
        same tuple is used to build the UDP reply and the forensic
        evidence row for that reply.  ``fast=True`` bounds lock waiting
        for the UDP hot path.
        """
        conn = self._connect_read() if fast else self._connect()
        try:
            conn.execute("BEGIN")
            serial = int(self._get_state(conn, "active_serial") or "0")
            row = conn.execute(
                "SELECT records_json, published_at FROM zone_versions "
                "WHERE serial=?",
                (serial,),
            ).fetchone()
            conn.execute("COMMIT")
            if row is None:
                # The pointer names a version that is not there (e.g. the DB
                # file was replaced/truncated). Never answer from a
                # fabricated empty zone; the resolver falls back to its last
                # complete snapshot or SERVFAIL.
                raise sqlite3.DatabaseError(
                    f"active zone version {serial} is missing"
                )
            records = json.loads(row["records_json"])
            return serial, records, (row["published_at"] if row else None)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def active_serial(self) -> int:
        serial, _, _ = self.get_active_version()
        return serial

    def get_sync_state(self) -> Dict[str, Any]:
        conn = self._connect()
        try:
            def g(key: str) -> Optional[str]:
                return self._get_state(conn, key)

            return {
                "active_serial": int(g("active_serial") or "0"),
                "last_sync_at": g("last_sync_at"),
                "last_sync_status": g("last_sync_status") or "never",
                "last_sync_error": g("last_sync_error"),
                "upstream_serial": (
                    int(g("upstream_serial"))
                    if g("upstream_serial") is not None
                    else None
                ),
            }
        finally:
            conn.close()

    def version_exists(self, serial: int) -> bool:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM zone_versions WHERE serial=?", (serial,)
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    # -- cross-file evidence loss marker --------------------------------
    def note_evidence_loss(self, start_at: str, lost: int,
                           error: str) -> None:
        """Persist evidence loss in the zone DB (a different file).

        Called by the evidence writer when it cannot write its own DB, so
        the "evidence incomplete" fact survives even if the evidence file
        stays unavailable. Losses accumulate: repeated failures widen the
        gap window and add up the record count. Best effort: never raises
        into the caller.
        """
        try:
            with self._lock:
                conn = self._connect()
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    raw = self._get_state(conn, "evidence_pending_loss")
                    prev_start = start_at
                    prev_lost = 0
                    if raw:
                        try:
                            old = json.loads(raw)
                            prev_start = min(
                                str(old.get("start_at") or start_at),
                                start_at,
                            )
                            prev_lost = int(old.get("lost_records") or 0)
                        except (ValueError, TypeError):
                            pass
                    payload = json.dumps(
                        {"start_at": prev_start,
                         "lost_records": prev_lost + lost,
                         "error": error},
                        separators=(",", ":"),
                    )
                    conn.execute(
                        "INSERT INTO state(key, value) "
                        "VALUES('evidence_pending_loss', ?) "
                        "ON CONFLICT(key) DO UPDATE "
                        "SET value=excluded.value",
                        (payload,),
                    )
                    conn.execute("COMMIT")
                except Exception:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
                finally:
                    conn.close()
        except Exception:  # pragma: no cover - best effort
            pass

    def take_evidence_loss(self) -> Optional[Dict[str, Any]]:
        """Read the persisted evidence-loss marker (does not clear it)."""
        try:
            conn = self._connect()
            try:
                raw = self._get_state(conn, "evidence_pending_loss")
            finally:
                conn.close()
            if not raw:
                return None
            data = json.loads(raw)
            return {
                "start_at": str(data.get("start_at") or utcnow_iso()),
                "lost_records": int(data.get("lost_records") or 0),
                "error": str(data.get("error") or "unknown"),
            }
        except Exception:  # pragma: no cover - best effort
            return None

    def clear_evidence_loss(self) -> None:
        """Drop the persisted loss marker after it has been recorded."""
        try:
            with self._lock:
                conn = self._connect()
                try:
                    conn.execute(
                        "DELETE FROM state WHERE key='evidence_pending_loss'"
                    )
                finally:
                    conn.close()
        except Exception:  # pragma: no cover - best effort
            pass

    # -- writes ---------------------------------------------------------
    def commit_version(
        self,
        serial: int,
        records: List[Dict[str, str]],
        published_at: str,
    ) -> bool:
        """Atomically store a version and make it the active one.

        Returns True when applied, False when rejected as a stale rollback.
        """
        if serial < 1:
            raise ValueError("serial must be a positive integer")
        payload = json.dumps(records, separators=(",", ":"), sort_keys=True)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                active = int(
                    self._get_state(conn, "active_serial") or "0"
                )
                if serial <= active:
                    # Late/old transfer or duplicate: never roll back.
                    conn.execute("COMMIT")
                    return False
                conn.execute(
                    "INSERT OR REPLACE INTO zone_versions "
                    "(serial, records_json, record_count, published_at) "
                    "VALUES (?, ?, ?, ?)",
                    (serial, payload, len(records), published_at),
                )
                conn.execute(
                    "UPDATE state SET value=? WHERE key='active_serial'",
                    (str(serial),),
                )
                conn.execute("COMMIT")
                return True
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def next_publish(
        self, records: List[Dict[str, str]]
    ) -> Tuple[int, str]:
        """Primary only: increment serial only after a valid publish."""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                next_serial = int(
                    self._get_state(conn, "active_serial") or "0"
                ) + 1
                published_at = utcnow_iso()
                conn.execute(
                    "INSERT INTO zone_versions "
                    "(serial, records_json, record_count, published_at) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        next_serial,
                        json.dumps(
                            records, separators=(",", ":"), sort_keys=True
                        ),
                        len(records),
                        published_at,
                    ),
                )
                conn.execute(
                    "UPDATE state SET value=? WHERE key='active_serial'",
                    (str(next_serial),),
                )
                conn.execute("COMMIT")
                return next_serial, published_at
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def update_sync_state(
        self,
        status: str,
        error: Optional[str],
        upstream_serial: Optional[int],
    ) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO state(key, value) VALUES('last_sync_at', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (utcnow_iso(),),
                )
                conn.execute(
                    "INSERT INTO state(key, value) "
                    "VALUES('last_sync_status', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (status,),
                )
                conn.execute(
                    "INSERT INTO state(key, value) "
                    "VALUES('last_sync_error', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (error or "",),
                )
                if upstream_serial is not None:
                    conn.execute(
                        "INSERT INTO state(key, value) "
                        "VALUES('upstream_serial', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (str(upstream_serial),),
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()


storage = Storage(settings.db_path)
