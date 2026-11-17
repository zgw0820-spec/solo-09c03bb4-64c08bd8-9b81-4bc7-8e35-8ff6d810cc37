"""Forensic evidence of UDP A answers.

Every answer served by the UDP resolver records, in the same code path and
from the very same immutable zone snapshot that built the reply:

* client (observed UDP source IP),
* query time (UTC),
* query name and qtype,
* the rcode that was actually sent,
* the A addresses put in the answer (empty for NXDOMAIN/NODATA),
* the zone serial the answer was built from.

Writes go through a bounded in-memory queue to a **separate** SQLite file
(``EVIDENCE_DB_PATH``), so a burst or a temporarily unwritable/locked
evidence database never slows down or fails UDP resolution, publishing or
sync. Records are dropped only when the queue is full; every drop is
counted and persisted as an ``evidence_markers`` row for its time window.
On restart the downtime window is marked as a gap before serving again,
and losses that happened while the evidence file was unwritable are also
remembered in the *zone* database (a different file), so they survive a
restart. An empty result set can therefore never be silently mistaken for
"the client did not query".

Because both the reply and the evidence row are derived from one tuple
returned by ``Storage.get_active_version()`` (a single read snapshot),
they always refer to the same zone serial.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .config import settings
from .storage import storage as zone_storage

log = logging.getLogger("evidence")

_UTC = timezone.utc


def utc_iso(dt: Optional[datetime] = None) -> str:
    return (dt or datetime.now(_UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _connect(path: str) -> sqlite3.Connection:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    timeout = max(0.1, settings.evidence_db_timeout_ms / 1000.0)
    conn = sqlite3.connect(path, timeout=timeout, isolation_level=None,
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(f"PRAGMA busy_timeout={int(timeout * 1000)}")
    return conn


@dataclass(frozen=True)
class QueryEvidence:
    at: str                     # UTC ISO-8601, seconds precision
    client_ip: str              # observed UDP source address
    qname: str                  # normalised (lower-case, no trailing dot)
    qtype: str
    rcode: str                  # rcode actually sent in this reply
    addresses: List[str]        # A rdata put in this reply (may be empty)
    serial: int                 # zone serial this reply was built from
    role: str

    def as_row(self) -> tuple:
        return (
            self.at,
            self.client_ip,
            self.qname,
            self.qtype,
            self.rcode,
            json.dumps(self.addresses, separators=(",", ":")),
            self.serial,
            self.role,
        )


class EvidenceLog:
    """Bounded, non-blocking evidence writer with explicit gap markers."""

    def __init__(self, path: str, capacity: int) -> None:
        self.path = path
        self.capacity = max(1, capacity)
        self._q: "queue.Queue[QueryEvidence]" = queue.Queue(self.capacity)
        self._drop_lock = threading.Lock()
        self._gap_lock = threading.Lock()
        self._inflight_lock = threading.Lock()
        self._progress_lock = threading.Lock()
        self._reset_runtime_state()

    def _reset_runtime_state(self) -> None:
        self._dropped = 0            # pending, not yet persisted
        self._dropped_total = 0      # since process start
        self._drop_first: Optional[str] = None
        self._drop_marked = False    # a marker for current drops is on disk
        self._write_errors = 0
        self._gap_start: Optional[str] = None
        self._gap_lost = 0
        self._stop = threading.Event()
        self._writer: Optional[threading.Thread] = None
        self._ready = False
        self._inflight = 0
        # Progress counters: record() increments accepted once a record is
        # in the queue; the writer increments resolved after the batch is
        # committed or explicitly recorded as lost. The read API waits for
        # accepted == resolved, closing the dequeue/commit race.
        self._accepted = 0
        self._resolved = 0
        self._last_write_error = "unknown"
        self._last_loss_note = 0.0
        # Earliest instant this evidence file is known to cover; windows
        # starting earlier are reported incomplete instead of "no query".
        self.coverage_start: Optional[str] = None
        self.boot_at: Optional[str] = None
        # Start of a period during which the evidence DB was unreachable;
        # closed with a marker once the writer can write again.
        self._outage_start: Optional[str] = None

    # -- lifecycle ------------------------------------------------------
    def init_schema(self) -> None:
        """Create tables and persist the downtime gap. Retries in background
        if the evidence DB is unavailable at startup (DNS keeps serving)."""
        self.boot_at = utc_iso()
        self._outage_start = None
        try:
            self._init_schema_once(at_startup=True)
            self._ready = True
        except Exception as exc:
            # Remember when evidence recording became impossible so the
            # whole outage is marked once the DB recovers, even if no
            # query happened while it was down.
            self._outage_start = self.boot_at
            log.error("evidence DB unavailable at startup (%s); "
                      "will retry in background", exc)
            self._ready = False

    def _ensure_schema(self) -> None:
        """Create tables only (no startup-gap logic); safe to call often."""
        conn = _connect(self.path)
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence_queries (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    at        TEXT    NOT NULL,
                    client_ip TEXT    NOT NULL,
                    qname     TEXT    NOT NULL,
                    qtype     TEXT    NOT NULL,
                    rcode     TEXT    NOT NULL,
                    addresses TEXT    NOT NULL,
                    serial    INTEGER NOT NULL,
                    role      TEXT    NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_at
                    ON evidence_queries(at);
                CREATE INDEX IF NOT EXISTS idx_evidence_client_at
                    ON evidence_queries(client_ip, at);
                CREATE TABLE IF NOT EXISTS evidence_markers (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind     TEXT NOT NULL,
                    start_at TEXT NOT NULL,
                    end_at   TEXT NOT NULL,
                    details  TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
        finally:
            conn.close()

    def _init_schema_once(self, at_startup: bool = False) -> None:
        # Also retried by the writer when the evidence DB was unavailable
        # at startup. Markers/coverage are written in one transaction with
        # the heartbeat so a restart cannot lose the gap bookkeeping.
        # ``at_startup`` only labels a recovered in-process outage.
        self._ensure_schema()
        conn = _connect(self.path)
        try:
            now = utc_iso()
            exists = conn.execute(
                "SELECT 1 FROM evidence_queries LIMIT 1"
            ).fetchone()
            first_alive = conn.execute(
                "SELECT value FROM evidence_meta "
                "WHERE key='first_alive_at'"
            ).fetchone()
            prev = conn.execute(
                "SELECT value FROM evidence_meta WHERE key='last_alive_at'"
            ).fetchone()
            pending = zone_storage.take_evidence_loss()
            conn.execute("BEGIN IMMEDIATE")
            try:
                if first_alive is None:
                    conn.execute(
                        "INSERT INTO evidence_meta(key, value) "
                        "VALUES('first_alive_at', ?)",
                        (now,),
                    )
                if self._outage_start is not None:
                    self._insert_marker(
                        conn, "evidence_db_unavailable",
                        self._outage_start, now,
                        {"reason": "evidence DB unreachable at startup; "
                                   "answers during this period were not "
                                   "recorded"},
                    )
                    self._outage_start = None
                elif exists is None:
                    # New evidence file, first successful write: no record
                    # can exist before this instant. Windows starting
                    # earlier are reported as uncovered, never as "no
                    # query".
                    self.coverage_start = self.boot_at or now
                elif first_alive is not None:
                    self.coverage_start = first_alive["value"]
                if prev is not None and prev["value"] <= now:
                    # The process/evidence writer was not running between
                    # the last heartbeat and this start: any query in that
                    # window is missing. Second precision means an
                    # immediate restart marks that second conservatively.
                    self._insert_marker(
                        conn, "startup_gap", prev["value"], now,
                        {"reason": "process_not_running"},
                    )
                if pending is not None:
                    self._insert_marker(
                        conn, "write_failure", pending["start_at"], now,
                        {"error": pending["error"],
                         "lost_records": pending["lost_records"],
                         "recovered_after_restart": at_startup},
                    )
                # An unreachable-evidence period that started at boot ends
                # the moment bookkeeping can be written again.
                if self._outage_start is not None:
                    self._insert_marker(
                        conn, "evidence_db_unavailable",
                        self._outage_start, now,
                        {"reason": "evidence DB unreachable at startup; "
                                   "answers during this period were not "
                                   "recorded"},
                    )
                    self._outage_start = None
                conn.execute(
                    "INSERT INTO evidence_meta(key, value) "
                    "VALUES('last_alive_at', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (now,),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            if pending is not None:
                zone_storage.clear_evidence_loss()
                # The loss is now in the evidence file; drop the in-memory
                # duplicate so the next batch does not report it twice.
                with self._gap_lock:
                    if self._gap_start is None or (
                        self._gap_start >= pending["start_at"]
                    ):
                        self._gap_start = None
                        self._gap_lost = 0
        finally:
            conn.close()

    @staticmethod
    def _insert_marker(conn: sqlite3.Connection, kind: str,
                       start_at: str, end_at: str, details: Dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO evidence_markers"
            "(kind, start_at, end_at, details, recorded_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (kind, start_at, end_at,
             json.dumps(details, separators=(",", ":")), utc_iso()),
        )

    def start(self) -> None:
        self._stop.clear()
        self._writer = threading.Thread(
            target=self._run, name="evidence-writer", daemon=True
        )
        self._writer.start()

    def stop(self, drain_timeout: float = 3.0) -> None:
        self._stop.set()
        if self._writer is not None:
            self._writer.join(timeout=drain_timeout)
        # Anything still queued could not be written in time (e.g. the
        # evidence DB is unwritable at shutdown). Persist the loss in the
        # zone DB so the next start reports it as a gap instead of losing
        # it silently.
        leftover: List[QueryEvidence] = []
        while True:
            try:
                leftover.append(self._q.get_nowait())
            except queue.Empty:
                break
        if leftover:
            self._add_pending_loss(
                leftover[0].at, len(leftover),
                "shutdown while evidence DB unavailable/queue not drained",
            )
        # Final heartbeat: the next startup then only marks the time the
        # process was genuinely down as a gap.
        try:
            conn = _connect(self.path)
            try:
                conn.execute(
                    "INSERT INTO evidence_meta(key, value) "
                    "VALUES('last_alive_at', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (utc_iso(),),
                )
            finally:
                conn.close()
        except Exception:  # pragma: no cover - shutdown must not fail
            pass

    # -- hot path (called from the UDP resolver) ------------------------
    def record(self, ev: QueryEvidence) -> None:
        """Never blocks, never raises, never touches SQLite."""
        with self._progress_lock:
            # Count as accepted before enqueueing so a concurrent reader
            # either sees the queue entry or waits for it to be resolved.
            self._accepted += 1
        try:
            self._q.put_nowait(ev)
        except queue.Full:
            with self._progress_lock:
                self._accepted -= 1
            # Bounded: drop the newest record but make the loss explicit.
            # The writer thread notices the counter (it polls every flush
            # interval) and persists a buffer_overflow marker; no SQLite
            # work ever happens on the resolver thread.
            with self._drop_lock:
                self._dropped += 1
                self._dropped_total += 1
                if self._drop_first is None:
                    self._drop_first = ev.at

    def _maybe_note_drop_marker(self, now: str) -> None:
        """Write a buffer_overflow marker for currently pending drops.

        Called from the writer thread only, so the resolver hot path never
        touches SQLite. The marker is committed directly on a connection
        (no explicit transaction), so it cannot hold a write lock.
        """
        if not self._ready:
            return
        with self._drop_lock:
            if self._drop_marked or not self._dropped:
                return
            self._drop_marked = True
            start = self._drop_first or now
            dropped = self._dropped
        try:
            self._ensure_schema()
            conn = _connect(self.path)
            try:
                self._insert_marker(
                    conn, "buffer_overflow", start, now,
                    {"dropped_records_at_least": dropped,
                     "capacity": self.capacity},
                )
            finally:
                conn.close()
        except Exception:  # pragma: no cover - best effort
            with self._drop_lock:
                self._drop_marked = False
            return
        with self._drop_lock:
            # The persisted marker accounts for the drops seen so far; a
            # later overflow episode gets its own marker.
            self._dropped = max(0, self._dropped - dropped)
            self._drop_marked = False
            if self._dropped == 0:
                self._drop_first = None

    def stats(self) -> Dict[str, Any]:
        with self._drop_lock:
            dropped = self._dropped_total
            pending_dropped = self._dropped
        with self._gap_lock:
            pending_gap = self._gap_lost
        with self._progress_lock:
            inflight = self._inflight
            pending = max(0, self._accepted - self._resolved)
        return {
            "buffered": self._q.qsize(),
            "inflight": inflight,
            "pending": pending,
            "capacity": self.capacity,
            "dropped_total": dropped,
            "pending_drop_marker": pending_dropped,
            "pending_gap_lost": pending_gap,
            "write_errors": self._write_errors,
            "db_ready": self._ready,
            "coverage_start": self.coverage_start,
        }

    # -- writer thread ---------------------------------------------------
    def _run(self) -> None:
        if not self._ready:
            try:
                self._init_schema_once()
                self._ready = True
            except Exception as exc:
                log.error("evidence DB still unavailable: %s", exc)
        conn: Optional[sqlite3.Connection] = None
        last_beat = 0.0
        last_connect_attempt = 0.0

        while not self._stop.is_set() or not self._q.empty():
            batch: List[QueryEvidence] = []
            timeout = max(0.01, settings.evidence_flush_interval_ms / 1000.0)
            try:
                batch.append(self._q.get(timeout=timeout))
            except queue.Empty:
                pass
            while len(batch) < max(1, settings.evidence_batch_size):
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break

            if batch:
                with self._inflight_lock:
                    self._inflight += len(batch)
            if batch or self._pending_drops() or self._pending_gap():
                if conn is None:
                    last_connect_attempt = time.monotonic()
                    try:
                        if not self._ready:
                            # Recovery path: DB reachable again. Re-run
                            # startup bookkeeping so the outage becomes an
                            # explicit gap.
                            self._init_schema_once()
                        conn = _connect(self.path)
                        self._ready = True
                    except Exception as exc:
                        # Bounded queue cannot hold the batch; count it as
                        # lost and keep serving (marker is retried).
                        if self._outage_start is None:
                            self._outage_start = utc_iso()
                        self._fail_batch(batch, exc)
                        with self._inflight_lock:
                            self._inflight -= len(batch)
                        self._mark_resolved(len(batch))
                        self._stop.wait(settings.evidence_retry_ms / 1000.0)
                        continue
                else:
                    self._close_outage(conn)
                try:
                    self._write_batch(conn, batch)
                    self._ready = True
                    self._write_errors = 0
                except Exception as exc:
                    if self._outage_start is None:
                        self._outage_start = utc_iso()
                    self._fail_batch(batch, exc)
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = None
                    self._mark_resolved(len(batch))
                    self._stop.wait(settings.evidence_retry_ms / 1000.0)
                    continue
                finally:
                    with self._inflight_lock:
                        self._inflight -= len(batch)
                self._mark_resolved(len(batch))

            # Overflow marker: written only here (writer thread), so the
            # resolver hot path never touches SQLite.
            if self._pending_drop_marker() and self._ready:
                self._maybe_note_drop_marker(utc_iso())

            # If nothing was lost there is still an outage window to close
            # once the DB is writable again (e.g. no query was served).
            if conn is not None and self._outage_start is not None:
                self._close_outage(conn)

            # While the evidence DB is unreachable, keep retrying even if
            # there is no queued work: readiness and the outage marker
            # must recover on their own.
            if conn is None and self._stop.is_set() is False:
                retry = time.monotonic()
                if retry - last_connect_attempt >= (
                    settings.evidence_retry_ms / 1000.0
                ):
                    last_connect_attempt = retry
                    try:
                        if not self._ready:
                            self._init_schema_once()
                        conn = _connect(self.path)
                        self._ready = True
                        self._write_errors = 0
                    except Exception:
                        conn = None

            now = time.monotonic()
            if now - last_beat > 1.0 and conn is not None:
                try:
                    # Heartbeat bounds the gap marked after a crash/restart.
                    conn.execute(
                        "INSERT INTO evidence_meta(key, value) "
                        "VALUES('last_alive_at', ?) "
                        "ON CONFLICT(key) DO UPDATE "
                        "SET value=excluded.value",
                        (utc_iso(),),
                    )
                    last_beat = now
                except Exception:
                    pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    def _close_outage(self, conn: sqlite3.Connection) -> None:
        """Mark the whole unreachable-evidence period once writes work."""
        if self._outage_start is None:
            return
        start, self._outage_start = self._outage_start, None
        try:
            self._insert_marker(
                conn, "evidence_db_unavailable", start, utc_iso(),
                {"reason": "evidence DB unreachable; answers during this "
                           "period were not recorded"},
            )
        except Exception:  # pragma: no cover - retry next loop
            self._outage_start = start

    def _pending_drops(self) -> int:
        with self._drop_lock:
            return self._dropped

    def _mark_resolved(self, n: int) -> None:
        if n <= 0:
            return
        with self._progress_lock:
            self._resolved += n

    def _pending_gap(self) -> int:
        with self._gap_lock:
            return self._gap_lost

    def _pending_drop_marker(self) -> bool:
        with self._drop_lock:
            return self._dropped > 0 and not self._drop_marked

    def _flush_now(self, timeout: float = 1.0) -> bool:
        """Wait until all accepted evidence is committed or recorded lost.

        Used by the forensic read API so an answer served a moment ago is
        visible. Never blocks the resolver (different thread). Returns
        False if it gave up after ``timeout``; ``query`` then reports the
        remainder as an explicit "pending_uncommitted" gap.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._progress_lock:
                if self._accepted == self._resolved:
                    return True
            if not self._ready and self._q.empty():
                # Writer cannot commit: pending records will be counted as
                # lost, so only a DB recovery could resolve them. Keep
                # waiting cheaply until the deadline (recovery is checked by
                # the writer every EVIDENCE_RETRY_MS).
                pass
            time.sleep(0.01)
        with self._progress_lock:
            return self._accepted == self._resolved
    def _fail_batch(self, batch: List[QueryEvidence],
                    exc: Exception) -> None:
        """Remember lost records; the marker is written once writes work."""
        self._write_errors += 1
        self._last_write_error = f"{type(exc).__name__}: {exc}"
        log.error("evidence write failed (%s records): %s", len(batch), exc)
        start = batch[0].at if batch else utc_iso()
        self._add_pending_loss(start, len(batch), self._last_write_error)

    def _add_pending_loss(self, start: str, lost: int, error: str) -> None:
        """Track lost records in memory and persist them in the zone DB.

        The zone DB is a different file from the evidence DB, so a loss
        survives even if the evidence file stays unwritable until a
        restart. It is consumed once an evidence marker is committed.
        Cross-file writes are rate-limited (once a second, or immediately
        when records were actually lost) to avoid write amplification
        while the evidence file remains unavailable.
        """
        now = time.monotonic()
        should_persist = lost > 0 or now - self._last_loss_note >= 1.0
        if should_persist:
            self._last_loss_note = now
            try:
                zone_storage.note_evidence_loss(start, lost, error)
            except Exception:  # pragma: no cover - never break writer
                log.exception("could not persist pending evidence loss")
        with self._gap_lock:
            if self._gap_start is None or start < self._gap_start:
                self._gap_start = start
            self._gap_lost += lost

    def _write_batch(self, conn: sqlite3.Connection,
                     batch: List[QueryEvidence]) -> None:
        conn.execute("BEGIN IMMEDIATE")
        with self._gap_lock:
            gap_start = self._gap_start
            gap_lost = self._gap_lost
        try:
            conn.executemany(
                "INSERT INTO evidence_queries"
                "(at, client_ip, qname, qtype, rcode, addresses, serial, role) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [ev.as_row() for ev in batch],
            )
            now = utc_iso()
            if gap_start:
                self._insert_marker(
                    conn, "write_failure", gap_start, now,
                    {"error": self._last_write_error,
                     "lost_records": gap_lost},
                )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        # Counters are cleared only after a successful commit; a rollback
        # leaves them pending so the next attempt re-reports the loss.
        if gap_start:
            with self._gap_lock:
                if self._gap_start == gap_start:
                    self._gap_start = None
                    self._gap_lost = 0
            try:
                zone_storage.clear_evidence_loss()
            except Exception:  # pragma: no cover
                pass

    # -- read side (forensics API) ---------------------------------------
    def query(self, client_ip: str, start: str, end: str,
              qname: Optional[str] = None) -> Dict[str, Any]:
        # Include records still in the writer's hand (dequeued but not yet
        # committed) by flushing first: the caller gets everything this
        # process already accepted, so a just-served answer is never
        # reported missing.
        flushed = self._flush_now()
        try:
            result = self._query_db(client_ip, start, end, qname)
        except (sqlite3.Error, OSError) as exc:
            # Evidence DB unreadable: report it as an explicit gap rather
            # than an empty result that looks like "no query".
            return {
                "client_ip": client_ip,
                "window": {"start": start, "end": end},
                "qname": qname,
                "records": [],
                "evidence_complete": False,
                "gaps": [{
                    "kind": "evidence_db_unavailable",
                    "start_at": start,
                    "end_at": end,
                    "details": {"error": f"{type(exc).__name__}: {exc}"},
                    "recorded_at": None,
                }],
                "pending": self._pending_count(),
            }
        pending = self._pending_count()
        if pending and (not flushed or not result["evidence_complete"]):
            # Some accepted answers are still not committed. They may or
            # may not be inside the window, so the result is not complete.
            result["gaps"].append({
                "kind": "pending_uncommitted",
                "start_at": start,
                "end_at": utc_iso(),
                "details": {"pending": pending},
                "recorded_at": None,
            })
            result["evidence_complete"] = False
        result["pending"] = pending
        return result

    def _pending_count(self) -> int:
        with self._progress_lock:
            return max(0, self._accepted - self._resolved)

    def _query_db(self, client_ip: str, start: str, end: str,
                  qname: Optional[str]) -> Dict[str, Any]:
        conn = _connect(self.path)
        try:
            params: List[Any] = [client_ip, start, end]
            where = "client_ip=? AND at>=? AND at<=?"
            if qname:
                where += " AND qname=?"
                params.append(qname)
            rows = conn.execute(
                "SELECT at, client_ip, qname, qtype, rcode, addresses, "
                "serial, role FROM evidence_queries WHERE " + where +
                " ORDER BY at, id",
                params,
            ).fetchall()
            markers = conn.execute(
                "SELECT kind, start_at, end_at, details, recorded_at "
                "FROM evidence_markers WHERE start_at<=? AND end_at>=? "
                "ORDER BY start_at",
                (end, start),
            ).fetchall()
        finally:
            conn.close()
        records = []
        for r in rows:
            records.append({
                "queried_at": r["at"],
                "client_ip": r["client_ip"],
                "qname": r["qname"],
                "qtype": r["qtype"],
                "rcode": r["rcode"],
                "addresses": json.loads(r["addresses"]),
                "serial": r["serial"],
                "role": r["role"],
            })
        gaps = [
            {
                "kind": m["kind"],
                "start_at": m["start_at"],
                "end_at": m["end_at"],
                "details": json.loads(m["details"]),
                "recorded_at": m["recorded_at"],
            }
            for m in markers
        ]
        # Time before this evidence file existed is not covered either: an
        # empty result there must not be read as "client did not query".
        if self.coverage_start and start < self.coverage_start:
            coverage_end = min(end, self.coverage_start)
            gaps.insert(0, {
                "kind": "before_coverage",
                "start_at": start,
                "end_at": coverage_end,
                "details": {"reason": "no_evidence_recorded_before_start"},
                "recorded_at": None,
            })
        return {
            "client_ip": client_ip,
            "window": {"start": start, "end": end},
            "qname": qname,
            "records": records,
            "evidence_complete": not gaps,
            "gaps": gaps,
        }


evidence_log = EvidenceLog(settings.evidence_path, settings.evidence_buffer_size)
