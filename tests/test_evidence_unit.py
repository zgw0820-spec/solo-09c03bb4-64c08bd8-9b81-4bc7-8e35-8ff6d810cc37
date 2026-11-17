"""Unit tests for the forensic evidence store.

These exercise the bounded buffer, the gap markers and the query-side
rules with a real (temporary) SQLite file, without running the DNS/API
processes (those are covered by ``tests/evidence_test.py``).
"""
import importlib
import time

import pytest


@pytest.fixture()
def ev(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "zone.db"))
    monkeypatch.setenv("EVIDENCE_DB_PATH", str(tmp_path / "ev.db"))
    monkeypatch.setenv("EVIDENCE_BUFFER_SIZE", "100")
    monkeypatch.setenv("EVIDENCE_FLUSH_INTERVAL_MS", "20")
    import app.config as config
    import app.storage as storage_mod
    import app.evidence as evidence_mod

    importlib.reload(config)
    importlib.reload(storage_mod)
    importlib.reload(evidence_mod)
    log = evidence_mod.EvidenceLog(config.settings.evidence_path, 100)
    log.init_schema()
    log.start()
    yield log
    log.stop()


def rec(at, ip="203.0.113.7", name="db.internal.local", rcode="NOERROR",
        addresses=("10.0.0.11",), serial=1):
    from app.evidence import QueryEvidence

    return QueryEvidence(at, ip, name, "A", rcode, list(addresses),
                         serial, "primary")


def wide():
    return "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"


def test_evidence_roundtrip_and_fields(ev):
    ev.record(rec("2026-11-17T08:00:00Z"))
    start, end = wide()
    out = ev.query("203.0.113.7", ev.stats()["coverage_start"], end)
    assert out["evidence_complete"] is True
    assert len(out["records"]) == 1
    row = out["records"][0]
    assert row == {
        "queried_at": "2026-11-17T08:00:00Z",
        "client_ip": "203.0.113.7",
        "qname": "db.internal.local",
        "qtype": "A",
        "rcode": "NOERROR",
        "addresses": ["10.0.0.11"],
        "serial": 1,
        "role": "primary",
    }


def test_empty_result_before_coverage_is_incomplete(ev):
    start, end = wide()
    out = ev.query("198.51.100.1", start, end)
    # Nothing recorded before this file existed: must not claim "no query".
    assert out["records"] == []
    assert out["evidence_complete"] is False
    kinds = {g["kind"] for g in out["gaps"]}
    assert "before_coverage" in kinds


def test_empty_result_within_coverage_is_complete(ev):
    ev.record(rec("2026-11-17T08:00:00Z"))
    ev.query("203.0.113.7", *wide())  # flush
    out = ev.query("198.51.100.1", "2026-11-17T08:00:00Z",
                   "2026-11-17T09:00:00Z")
    assert out["records"] == []
    assert out["evidence_complete"] is True


def test_filter_by_client_and_qname_is_exact(ev):
    ev.record(rec("2026-11-17T08:00:01Z", ip="10.0.0.1"))
    ev.record(rec("2026-11-17T08:00:02Z", ip="10.0.0.2"))
    ev.record(rec("2026-11-17T08:00:03Z", ip="10.0.0.1",
                  name="web.internal.local"))
    out = ev.query("10.0.0.1", *wide())
    assert len(out["records"]) == 2
    out = ev.query("10.0.0.1", *wide(), qname="web.internal.local")
    assert len(out["records"]) == 1
    assert out["records"][0]["qname"] == "web.internal.local"


def test_bounded_buffer_drops_and_marks_overflow(monkeypatch, tmp_path):
    import importlib

    monkeypatch.setenv("DB_PATH", str(tmp_path / "z.db"))
    monkeypatch.setenv("EVIDENCE_DB_PATH", str(tmp_path / "e2.db"))
    import app.config as config
    import app.evidence as evidence_mod

    importlib.reload(config)
    importlib.reload(evidence_mod)
    log = evidence_mod.EvidenceLog(config.settings.evidence_path, 3)
    log.init_schema()
    # Writer not started yet: the queue is bounded and overflow is counted.
    for i in range(10):
        log.record(rec(f"2026-11-17T08:00:{i:02d}Z"))
    stats = log.stats()
    assert stats["buffered"] == 3
    assert stats["dropped_total"] == 7
    log.start()
    time.sleep(0.6)
    out = log.query("203.0.113.7", *wide())
    log.stop()
    assert len(out["records"]) == 3
    assert out["evidence_complete"] is False
    overflow = [g for g in out["gaps"] if g["kind"] == "buffer_overflow"]
    assert overflow and overflow[0]["details"]["dropped_records_at_least"] == 7


def test_restart_marks_downtime_gap(tmp_path, monkeypatch):
    import importlib

    monkeypatch.setenv("DB_PATH", str(tmp_path / "z.db"))
    monkeypatch.setenv("EVIDENCE_DB_PATH", str(tmp_path / "e3.db"))
    import app.config as config
    import app.evidence as evidence_mod

    importlib.reload(config)
    importlib.reload(evidence_mod)
    first = evidence_mod.EvidenceLog(config.settings.evidence_path, 10)
    first.init_schema()
    first.start()
    first.record(rec("2026-11-17T08:00:00Z"))
    first.query("203.0.113.7", *wide())  # flush
    first.stop()
    time.sleep(1.1)

    second = evidence_mod.EvidenceLog(config.settings.evidence_path, 10)
    second.init_schema()
    second.start()
    try:
        out = second.query("203.0.113.7", *wide())
        assert len(out["records"]) == 1  # old evidence preserved
        gaps = [g for g in out["gaps"] if g["kind"] == "startup_gap"]
        assert gaps, out["gaps"]
        assert gaps[0]["start_at"] <= gaps[0]["end_at"]
    finally:
        second.stop()


def test_query_reports_db_unavailable_instead_of_empty(tmp_path, monkeypatch):
    import importlib

    blocker = tmp_path / "blocked"
    blocker.write_text("")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "z.db"))
    monkeypatch.setenv(
        "EVIDENCE_DB_PATH", str(blocker / "sub" / "ev.db")
    )
    import app.config as config
    import app.evidence as evidence_mod

    importlib.reload(config)
    importlib.reload(evidence_mod)
    log = evidence_mod.EvidenceLog(config.settings.evidence_path, 10)
    log.init_schema()  # fails gracefully
    assert log.stats()["db_ready"] is False
    out = log.query("203.0.113.7", *wide())
    assert out["records"] == []
    assert out["evidence_complete"] is False
    assert out["gaps"][0]["kind"] == "evidence_db_unavailable"
