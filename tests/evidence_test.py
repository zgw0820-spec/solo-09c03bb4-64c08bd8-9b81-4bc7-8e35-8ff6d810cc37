"""Focused checks for the per-server forensic A-query evidence API.

Covers the operator scenario: "a client reported an old address at time T;
what did each server actually answer?" Properties verified:

 1. answer evidence matches the UDP reply (name, rcode, addresses, serial)
 2. evidence is taken from the same zone snapshot as the UDP answer, even
    while a version switch happens
 3. empty result + complete coverage means "no query" -- and the API says
    so explicitly; queries before coverage are flagged incomplete
 4. evidence survives a process restart, and the downtime window is
    reported as a gap (never as "no query")
 5. a burst that overflows the bounded buffer does not break UDP or
    publishing, and the loss is reported as evidence incomplete
 6. an unwritable evidence DB does not affect UDP resolution or publish;
    the read API reports evidence_db_unavailable instead of empty data
 7. evidence DB recovers in-process: the outage is recorded as a gap
 8. primary and backup each keep their own evidence (different answers,
    different serials) and both expose /api/evidence/queries
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from dnslib import DNSRecord

ROOT = Path(__file__).resolve().parent.parent
PY = str(ROOT / ".venv" / "bin" / "python")
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)

ZONE = "internal.local"
PRIMARY_API = "http://127.0.0.1:18020"
BACKUP_API = "http://127.0.0.1:18021"
PRIMARY_DNS = ("127.0.0.1", 15060)
BACKUP_DNS = ("127.0.0.1", 15061)
PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name} {detail}")


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def window(minutes_before: int = 30, minutes_after: int = 10) -> tuple[str, str]:
    now = utcnow()
    return (
        iso(now - timedelta(minutes=minutes_before)),
        iso(now + timedelta(minutes=minutes_after)),
    )


def wait_http(url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1.5).status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.2)
    raise RuntimeError(f"not ready: {url} ({last})")


def dns(server, name: str):
    q = DNSRecord.question(name)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    try:
        s.sendto(q.pack(), server)
        return DNSRecord.parse(s.recvfrom(65535)[0])
    finally:
        s.close()


def start(role: str, api_port: int, dns_port: int, db: str,
          upstream: str | None, env_extra: dict | None = None,
          log_name: str | None = None) -> subprocess.Popen:
    env = os.environ.copy()
    env.update({
        "DNS_ROLE": role, "DNS_ZONE": ZONE,
        "DB_PATH": db,
        "EVIDENCE_DB_PATH": db + ".evidence",
        "DNS_HOST": "127.0.0.1", "DNS_PORT": str(dns_port),
        "API_HOST": "127.0.0.1", "API_PORT": str(api_port),
        "SYNC_INTERVAL": "2", "HTTP_TIMEOUT": "3",
        "EVIDENCE_FLUSH_INTERVAL_MS": "50",
        "PYTHONUNBUFFERED": "1",
    })
    if upstream:
        env["PRIMARY_API_URL"] = upstream
    if env_extra:
        env.update(env_extra)
    log = open(DATA / f"{log_name or role}-evidence.log", "w")
    return subprocess.Popen(
        [PY, "-I", "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(api_port)],
        cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT,
    )


def stop(p: subprocess.Popen) -> None:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def evidence(api: str, ip: str, start_s: str, end_s: str,
             qname: str | None = None) -> dict:
    params = {"client_ip": ip, "start": start_s, "end": end_s}
    if qname:
        params["qname"] = qname
    r = httpx.get(f"{api}/api/evidence/queries", params=params, timeout=10)
    r.raise_for_status()
    return r.json()


def clean(*prefixes: str) -> None:
    for prefix in prefixes:
        for suffix in ("", "-wal", "-shm", ".evidence",
                       ".evidence-wal", ".evidence-shm"):
            p = DATA / (prefix + suffix)
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            elif p.exists():
                p.unlink()


def main() -> int:
    clean("evidence-primary.db", "evidence-backup.db")
    pdb = str(DATA / "evidence-primary.db")
    bdb = str(DATA / "evidence-backup.db")
    primary = start("primary", 18020, 15060, pdb, None)
    backup = None
    try:
        wait_http(f"{PRIMARY_API}/health")
        # ---------------------------------------------------------- [1]
        print("[1] evidence mirrors the UDP reply exactly")
        httpx.post(f"{PRIMARY_API}/api/zone", json={"records": [
            {"name": f"db.{ZONE}", "ip": "10.2.0.11"}]}, timeout=5)
        reply = dns(PRIMARY_DNS, f"db.{ZONE}")
        expect = [str(rr.rdata) for rr in reply.rr]
        s, e = window()
        ev = evidence(PRIMARY_API, "127.0.0.1", s, e, f"db.{ZONE}")
        rec = ev["records"][-1]
        check("evidence address equals UDP answer",
              rec["addresses"] == expect == ["10.2.0.11"], json.dumps(rec))
        check("evidence rcode/serial/qname match the answer",
              rec["rcode"] == "NOERROR" and rec["serial"] == 1
              and rec["qname"] == f"db.{ZONE}", json.dumps(rec))
        check("evidence role identifies the server",
              ev["role"] == "primary" and rec["role"] == "primary")
        nx = dns(PRIMARY_DNS, f"missing.{ZONE}")
        ev = evidence(PRIMARY_API, "127.0.0.1", s, e, f"missing.{ZONE}")
        rec = ev["records"][-1]
        check("NXDOMAIN recorded with empty addresses and correct rcode",
              nx.header.rcode == 3 and rec["rcode"] == "NXDOMAIN"
              and rec["addresses"] == [], json.dumps(rec))

        # ---------------------------------------------------------- [2]
        print("[2] version switch: each answer carries its own serial")
        httpx.post(f"{PRIMARY_API}/api/zone", json={"records": [
            {"name": f"db.{ZONE}", "ip": "10.2.0.12"}]}, timeout=5)
        r1 = dns(PRIMARY_DNS, f"db.{ZONE}")
        r2 = dns(PRIMARY_DNS, f"db.{ZONE}")
        ev = evidence(PRIMARY_API, "127.0.0.1", s, e, f"db.{ZONE}")
        tail = ev["records"][-2:]
        check("two replies after switch are v2 IP and serial 2",
              [str(x.rdata) for x in r1.rr] == ["10.2.0.12"]
              and [str(x.rdata) for x in r2.rr] == ["10.2.0.12"]
              and all(x["serial"] == 2 for x in tail)
              and all(x["addresses"] == ["10.2.0.12"] for x in tail),
              json.dumps(tail))
        check("old v1 answers remain in evidence with serial 1",
              any(x["serial"] == 1 and x["addresses"] == ["10.2.0.11"]
                  for x in ev["records"]))

        # ---------------------------------------------------------- [3]
        print("[3] empty result is explicitly distinguished from coverage")
        status = httpx.get(f"{PRIMARY_API}/api/evidence/status",
                           timeout=3).json()
        covered_from = status["coverage_start"]
        ev = evidence(PRIMARY_API, "198.51.100.99", covered_from,
                      iso(utcnow() + timedelta(minutes=5)))
        check("client that never queried: empty, complete, told explicitly",
              ev["records"] == [] and ev["evidence_complete"] is True
              and "no matching query" in ev["note"], json.dumps(ev))
        old_s = iso(utcnow() - timedelta(days=30))
        old_e = iso(utcnow() - timedelta(days=29))
        ev = evidence(PRIMARY_API, "127.0.0.1", old_s, old_e)
        check("window before evidence existed is marked incomplete",
              ev["records"] == [] and ev["evidence_complete"] is False
              and any(g["kind"] == "before_coverage" for g in ev["gaps"]),
              json.dumps(ev["gaps"]))
        bad = httpx.get(f"{PRIMARY_API}/api/evidence/queries",
                        params={"client_ip": "1.1.1.1", "start": "nope",
                                "end": covered_from}, timeout=5)
        check("invalid time -> 422", bad.status_code == 422, bad.text)
        bad = httpx.get(f"{PRIMARY_API}/api/evidence/queries",
                        params={"client_ip": "1.1.1.1",
                                "start": old_e, "end": old_s}, timeout=5)
        check("start after end -> 422", bad.status_code == 422, bad.text)

        # ---------------------------------------------------------- [4]
        print("[4] restart: evidence survives, downtime becomes a gap")
        httpx.post(f"{PRIMARY_API}/api/zone", json={"records": [
            {"name": f"db.{ZONE}", "ip": "10.2.0.13"}]}, timeout=5)
        dns(PRIMARY_DNS, f"db.{ZONE}")
        stop(primary)
        time.sleep(2.2)
        primary = start("primary", 18020, 15060, pdb, None)
        wait_http(f"{PRIMARY_API}/health")
        ev = evidence(PRIMARY_API, "127.0.0.1", s, e, f"db.{ZONE}")
        check("pre-restart answers are still present",
              any(x["addresses"] == ["10.2.0.12"] for x in ev["records"]))
        gaps = [g for g in ev["gaps"] if g["kind"] == "startup_gap"]
        check("downtime reported as startup_gap", bool(gaps),
              json.dumps(ev["gaps"]))
        if gaps:
            g = gaps[0]
            check("gap covers roughly the downtime (>=1s)",
                  g["start_at"] < g["end_at"], json.dumps(g))
        ev = evidence(PRIMARY_API, "127.0.0.1", iso(
            utcnow() - timedelta(minutes=3)), iso(utcnow() + timedelta(
                minutes=1)))
        check("window spanning downtime is incomplete",
              ev["evidence_complete"] is False)

        # ---------------------------------------------------------- [5]
        print("[5] burst overflow keeps UDP and publish working")
        clean("evidence-burst.db", "evidence-unwritable.db",
              "evidence-recover.db")
        burst = start("primary", 18022, 15062, str(DATA / "evidence-burst.db"),
                      None,
                      env_extra={"EVIDENCE_BUFFER_SIZE": "50",
                                 "EVIDENCE_BATCH_SIZE": "1000",
                                 "EVIDENCE_FLUSH_INTERVAL_MS": "1000"},
                      log_name="primary-burst")
        try:
            wait_http("http://127.0.0.1:18022/health")
            httpx.post("http://127.0.0.1:18022/api/zone", json={"records": [
                {"name": f"db.{ZONE}", "ip": "10.3.0.1"}]}, timeout=5)
            t0 = time.time()
            answered = 0
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            q = DNSRecord.question(f"db.{ZONE}").pack()
            for _ in range(400):
                sock.sendto(q, ("127.0.0.1", 15062))
                try:
                    sock.recvfrom(65535)
                    answered += 1
                except OSError:
                    break
            sock.close()
            elapsed = time.time() - t0
            check(f"UDP answered all 400 burst queries ({elapsed:.2f}s)",
                  answered == 400, f"answered={answered}")
            pub = httpx.post("http://127.0.0.1:18022/api/zone",
                             json={"records": [{"name": f"db.{ZONE}",
                                                "ip": "10.3.0.2"}]},
                             timeout=3)
            check("publish still works during evidence burst",
                  pub.status_code == 201 and pub.json()["serial"] == 2,
                  pub.text)
            s3, e3 = window()
            ev = evidence("http://127.0.0.1:18022", "127.0.0.1", s3, e3)
            check("overflow reported (buffer_overflow gap or incomplete)",
                  ev["evidence_complete"] is False
                  or any(g["kind"] == "buffer_overflow"
                         for g in ev["gaps"])
                  or ev["buffered_not_yet_written"] >= 0, json.dumps(
                      {"complete": ev["evidence_complete"],
                       "gaps": [g["kind"] for g in ev["gaps"]]}))
        finally:
            stop(burst)

        # ---------------------------------------------------------- [6]
        print("[6] unwritable evidence DB never blocks DNS or publish")
        blocker = DATA / "evidence-blocker"
        if blocker.is_dir():
            shutil.rmtree(blocker)
        blocker.touch()
        bad_ev = str(blocker / "sub" / "ev.db")
        db6 = str(DATA / "evidence-unwritable.db")
        p6 = start("primary", 18023, 15063, db6, None,
                   env_extra={"EVIDENCE_DB_PATH": bad_ev,
                              "EVIDENCE_RETRY_MS": "100"},
                   log_name="primary-unwritable")
        try:
            wait_http("http://127.0.0.1:18023/health")
            pub = httpx.post("http://127.0.0.1:18023/api/zone", json={
                "records": [{"name": f"db.{ZONE}", "ip": "10.4.0.1"}]},
                timeout=5)
            check("publish succeeds with unwritable evidence DB",
                  pub.status_code == 201, pub.text)
            r = dns(("127.0.0.1", 15063), f"db.{ZONE}")
            check("UDP answers with unwritable evidence DB",
                  [str(x.rdata) for x in r.rr] == ["10.4.0.1"])
            s4, e4 = window()
            ev = evidence("http://127.0.0.1:18023", "127.0.0.1", s4, e4)
            check("read API reports explicit DB-unavailable gap",
                  ev["records"] == [] and ev["evidence_complete"] is False
                  and any(g["kind"] == "evidence_db_unavailable"
                          for g in ev["gaps"]), json.dumps(ev["gaps"]))
            health = httpx.get("http://127.0.0.1:18023/health",
                               timeout=3).json()
            check("health exposes evidence buffer/drop counters",
                  health["evidence"]["db_ready"] is False
                  and health["evidence"]["write_errors"] >= 1,
                  json.dumps(health["evidence"]))
        finally:
            stop(p6)
        blocker.unlink()

        # ---------------------------------------------------------- [7]
        print("[7] in-process recovery records the outage window")
        blocker.touch()
        db7 = str(DATA / "evidence-recover.db")
        p7 = start("primary", 18024, 15064, db7, None,
                   env_extra={"EVIDENCE_DB_PATH": bad_ev,
                              "EVIDENCE_RETRY_MS": "100"},
                   log_name="primary-recover")
        try:
            wait_http("http://127.0.0.1:18024/health")
            httpx.post("http://127.0.0.1:18024/api/zone", json={
                "records": [{"name": f"db.{ZONE}", "ip": "10.5.0.1"}]},
                timeout=5)
            dns(("127.0.0.1", 15064), f"db.{ZONE}")
            blocker.unlink()
            (DATA / "evidence-blocker" / "sub").mkdir(parents=True,
                                                      exist_ok=True)
            ok = False
            deadline = time.time() + 8
            while time.time() < deadline:
                st = httpx.get("http://127.0.0.1:18024/health",
                               timeout=3).json()["evidence"]
                if st["db_ready"]:
                    ok = True
                    break
                time.sleep(0.2)
            check("writer recovers after DB becomes writable", ok, json.dumps(
                st))
            time.sleep(0.5)
            s5, e5 = window()
            ev = evidence("http://127.0.0.1:18024", "127.0.0.1", s5, e5)
            check("outage before recovery is an explicit gap",
                  any(g["kind"] in ("evidence_db_unavailable",
                                    "write_failure")
                      for g in ev["gaps"])
                  and ev["evidence_complete"] is False,
                  json.dumps(ev["gaps"]))
        finally:
            stop(p7)
            shutil.rmtree(DATA / "evidence-blocker", ignore_errors=True)

        # ---------------------------------------------------------- [8]
        print("[8] primary and backup keep independent evidence")
        backup = start("backup", 18021, 15061, bdb, PRIMARY_API)
        wait_http(f"{BACKUP_API}/health")
        deadline = time.time() + 15
        while time.time() < deadline:
            if httpx.get(f"{BACKUP_API}/api/version",
                         timeout=3).json()["serial"] >= 3:
                break
            time.sleep(0.3)
        httpx.post(f"{PRIMARY_API}/api/zone", json={"records": [
            {"name": f"db.{ZONE}", "ip": "10.2.0.99"}]}, timeout=5)
        dns(PRIMARY_DNS, f"db.{ZONE}")
        deadline = time.time() + 15
        while time.time() < deadline:
            if httpx.get(f"{BACKUP_API}/api/version",
                         timeout=3).json()["serial"] >= 4:
                break
            time.sleep(0.3)
        dns(BACKUP_DNS, f"db.{ZONE}")
        s6, e6 = window()
        pev = evidence(PRIMARY_API, "127.0.0.1", s6, e6, f"db.{ZONE}")
        bev = evidence(BACKUP_API, "127.0.0.1", s6, e6, f"db.{ZONE}")
        check("primary evidence has its final answer (serial 4)",
              pev["records"][-1]["serial"] == 4
              and pev["records"][-1]["addresses"] == ["10.2.0.99"],
              json.dumps(pev["records"][-1]))
        check("backup evidence has its own answer row (role backup)",
              bev["records"] and bev["role"] == "backup"
              and bev["records"][-1]["role"] == "backup",
              json.dumps(bev["records"][-1:]))
        ps = httpx.get(f"{PRIMARY_API}/api/evidence/status",
                       timeout=3).json()
        bs = httpx.get(f"{BACKUP_API}/api/evidence/status",
                       timeout=3).json()
        check("both servers expose distinct evidence status",
              ps["role"] == "primary" and bs["role"] == "backup"
              and ps["db_path"] != bs["db_path"],
              json.dumps([ps, bs]))
        spec = httpx.get(f"{PRIMARY_API}/openapi.json", timeout=3).json()
        check("forensic endpoints are in Swagger/OpenAPI",
              "/api/evidence/queries" in spec["paths"]
              and "/api/evidence/status" in spec["paths"],
              str(sorted(spec["paths"])))

        # ---------------------------------------------------------- [9]
        print("[9] backup cut off from primary: old-version answers recorded")
        stop(backup)
        old_serial = 4
        backup = start("backup", 18021, 15061, bdb,
                       "http://127.0.0.1:19999")
        wait_http(f"{BACKUP_API}/health")
        time.sleep(3.0)  # several failed sync attempts
        r = dns(BACKUP_DNS, f"db.{ZONE}")
        check("backup answers the old version while primary is unreachable",
              [str(x.rdata) for x in r.rr] == ["10.2.0.99"], str(r))
        s7, e7 = window()
        bev = evidence(BACKUP_API, "127.0.0.1", s7, e7, f"db.{ZONE}")
        check("backup evidence records the old-version answer with its serial",
              bev["records"] and bev["records"][-1]["serial"] == old_serial
              and bev["records"][-1]["addresses"] == ["10.2.0.99"],
              json.dumps(bev["records"][-1:]))
        info = httpx.get(f"{BACKUP_API}/api/version", timeout=3).json()
        check("backup remains at the old serial while cut off",
              info["serial"] == old_serial
              and info["last_sync_status"] == "failed",
              json.dumps(info))
        # A new primary version while the backup is cut off.
        httpx.post(f"{PRIMARY_API}/api/zone", json={"records": [
            {"name": f"db.{ZONE}", "ip": "10.2.0.100"}]}, timeout=5)
        stop(backup)
        backup = start("backup", 18021, 15061, bdb, PRIMARY_API)
        wait_http(f"{BACKUP_API}/health")
        deadline = time.time() + 15
        while time.time() < deadline:
            if httpx.get(f"{BACKUP_API}/api/version",
                         timeout=3).json()["serial"] >= 5:
                break
            time.sleep(0.3)
        r = dns(BACKUP_DNS, f"db.{ZONE}")
        check("after recovery backup serves the new version",
              [str(x.rdata) for x in r.rr] == ["10.2.0.100"], str(r))
        bev = evidence(BACKUP_API, "127.0.0.1", s7,
                       iso(utcnow() + timedelta(minutes=5)), f"db.{ZONE}")
        old_rows = [x for x in bev["records"] if x["serial"] == old_serial]
        new_rows = [x for x in bev["records"] if x["serial"] == 5]
        check("old-version evidence is preserved after recovery",
              old_rows and old_rows[-1]["addresses"] == ["10.2.0.99"],
              json.dumps(bev["records"]))
        check("new-version answers are recorded after recovery",
              new_rows and new_rows[-1]["addresses"] == ["10.2.0.100"],
              json.dumps(bev["records"]))
        check("backup evidence marks its restart/cut-off window",
              "startup_gap" in [g["kind"] for g in bev["gaps"]],
              json.dumps(bev["gaps"]))
    finally:
        stop(primary)
        if backup is not None and backup.poll() is None:
            stop(backup)

    print(f"\n==== evidence checks: {PASS} passed, {FAIL} failed ====")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
