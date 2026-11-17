"""FastAPI entry point: REST API (with Swagger UI) + in-process UDP DNS."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Query

from .config import settings
from .dns_server import dns_service
from .evidence import evidence_log
from .models import (
    EvidenceQueryOut,
    EvidenceSourceOut,
    PublishResult,
    RecordOut,
    VersionOut,
    ZoneOut,
    ZonePayload,
)
from .storage import storage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("main")

# Window bounds are compared as strings, so normalise everything to the
# same second-precision UTC layout used when evidence is written.
def _parse_time(value: str, name: str) -> str:
    raw = value.strip()
    if not raw:
        raise HTTPException(
            status_code=422, detail=f"{name} must not be empty"
        )
    iso = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        dt = None
    if dt is None:
        # Accept a space instead of the ISO "T" separator.
        try:
            dt = datetime.fromisoformat(raw.replace(" ", "T", 1))
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"{name} must be an ISO-8601 time "
                    "(e.g. 2026-11-17T08:00:00Z)"
                ),
            ) from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _zone_out() -> ZoneOut:
    serial, records, published_at = storage.get_active_version()
    return ZoneOut(
        zone=settings.dns_zone,
        serial=serial,
        records=[RecordOut(**r) for r in records],
        published_at=published_at,
    )


def _version_out() -> VersionOut:
    serial, records, published_at = storage.get_active_version()
    sync_state = storage.get_sync_state()
    return VersionOut(
        role=settings.role,
        zone=settings.dns_zone,
        serial=serial,
        record_count=len(records),
        published_at=published_at,
        last_sync_at=sync_state["last_sync_at"],
        last_sync_status=sync_state["last_sync_status"],
        last_sync_error=sync_state["last_sync_error"] or None,
        upstream_serial=sync_state["upstream_serial"],
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "starting role=%s zone=%s db=%s dns_udp=%s api=%s",
        settings.role,
        settings.dns_zone,
        settings.db_path,
        settings.dns_port,
        settings.api_port,
    )
    # Evidence must be accepting records before the first answer goes out,
    # and DNS must stop before the evidence writer on shutdown, so there is
    # no window in which answered queries are silently unrecorded.
    evidence_log.init_schema()
    evidence_log.start()
    dns_service.start()
    if not settings.is_primary:
        from .sync import sync_loop

        await sync_loop.start()
    try:
        yield
    finally:
        if not settings.is_primary:
            from .sync import sync_loop

            await sync_loop.stop()
        dns_service.stop()
        evidence_log.stop()


app = FastAPI(
    title="Primary/Backup DNS for fixed intranet zone",
    version="1.0.0",
    description=(
        "Primary accepts a complete zone (up to 8 A records); the backup "
        "pulls whole versions over HTTP and answers A queries over UDP. "
        "Every answer uses one immutable version. Each role also exposes a "
        "forensic API that replays what this server actually answered for "
        "an in-zone A query by client IP and time window; the evidence row "
        "and the UDP reply come from the same zone snapshot, and periods "
        "whose evidence was lost are reported as explicit gaps."
    ),
    lifespan=lifespan,
)


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {
        "status": "ok",
        "role": settings.role,
        "zone": settings.dns_zone,
        "evidence": evidence_log.stats(),
    }


@app.get("/api/version", response_model=VersionOut, tags=["zone"])
def get_version() -> VersionOut:
    return _version_out()


@app.get("/api/zone", response_model=ZoneOut, tags=["zone"])
def get_zone() -> ZoneOut:
    return _zone_out()


@app.get(
    "/api/evidence/queries",
    response_model=EvidenceQueryOut,
    tags=["forensics"],
)
def get_evidence(
    client_ip: str = Query(
        ...,
        description="Client IP exactly as observed as the UDP source address.",
        examples=["203.0.113.7"],
    ),
    start: str = Query(
        ...,
        description="Inclusive window start (UTC ISO-8601).",
        examples=["2026-11-17T08:00:00Z"],
    ),
    end: str = Query(
        ...,
        description="Inclusive window end (UTC ISO-8601).",
        examples=["2026-11-17T09:00:00Z"],
    ),
    qname: Optional[str] = Query(
        None,
        description="Optional exact query name filter (case-insensitive, "
        "trailing dot ignored).",
    ),
    limit: int = Query(
        1000, ge=1, le=10000,
        description="Maximum records returned (oldest first).",
    ),
) -> EvidenceQueryOut:
    """Forensic replay of UDP answers for one client IP and time window.

    Answer to "what did this server actually answer at that time": query
    name, rcode, addresses and the zone serial used for each reply.

    ``evidence_complete`` is false when any part of the requested window
    has known evidence loss (buffer overflow, evidence DB write failure,
    or server downtime between runs); ``gaps`` describes those periods.
    An empty ``records`` list alone must not be read as "the client did
    not query" unless ``evidence_complete`` is true.
    """
    start_norm = _parse_time(start, "start")
    end_norm = _parse_time(end, "end")
    if start_norm > end_norm:
        raise HTTPException(
            status_code=422, detail="start must not be after end"
        )
    norm_name = qname.strip().rstrip(".").lower() if qname else None
    result = evidence_log.query(
        client_ip.strip(), start_norm, end_norm, norm_name or None
    )
    records = result["records"]
    truncated = len(records) > limit
    records = records[:limit]
    complete = result["evidence_complete"] and not truncated
    if not result["evidence_complete"]:
        note = ("evidence incomplete: known gaps overlap this window; "
                "records may be missing")
    elif truncated:
        note = ("evidence window has more records than limit; oldest "
                "records returned, narrow the window")
    else:
        note = ("evidence complete for this window: empty records means "
                "no matching query was answered")
    return EvidenceQueryOut(
        role=settings.role,
        zone=settings.dns_zone,
        client_ip=client_ip.strip(),
        window_start=start_norm,
        window_end=end_norm,
        qname=norm_name,
        records=records,
        evidence_complete=complete,
        gaps=result["gaps"],
        truncated=truncated,
        buffered_not_yet_written=result.get("pending", 0),
        note=note,
    )


@app.get(
    "/api/evidence/status",
    response_model=EvidenceSourceOut,
    tags=["forensics"],
)
def get_evidence_status() -> EvidenceSourceOut:
    """Evidence coverage of *this* server (role, DB, buffer health).

    Poll primary and backup separately to compare what each one answered.
    """
    stats = evidence_log.stats()
    return EvidenceSourceOut(
        role=settings.role,
        zone=settings.dns_zone,
        db_path=settings.evidence_path,
        coverage_start=stats["coverage_start"],
        buffer_capacity=stats["capacity"],
        buffered=stats["buffered"],
        inflight=stats["inflight"],
        dropped_total=stats["dropped_total"],
        write_errors=stats["write_errors"],
        db_ready=stats["db_ready"],
    )


# ---------------------------------------------------------------- primary
@app.post(
    "/api/zone",
    response_model=PublishResult,
    status_code=201,
    tags=["primary"],
)
def publish_zone(payload: ZonePayload) -> PublishResult:
    """Replace the whole zone. The serial increments only on success."""
    if not settings.is_primary:
        raise HTTPException(
            status_code=403,
            detail="zone publishing is only allowed on the primary",
        )
    records = [r.model_dump() for r in payload.sorted_records()]
    serial, published_at = storage.next_publish(records)
    log.info("published new version serial=%s records=%s",
             serial, len(records))
    return PublishResult(
        ok=True,
        serial=serial,
        record_count=len(records),
        published_at=published_at,
    )


# ----------------------------------------------------------------- backup
@app.post("/api/sync", tags=["backup"])
async def manual_sync() -> dict:
    """Pull the complete current zone from the primary once."""
    if settings.is_primary:
        raise HTTPException(
            status_code=403,
            detail="sync is only available on the backup",
        )
    from .sync import sync_loop

    outcome = await sync_loop.trigger()
    result = outcome.as_dict()
    result["zone"] = _zone_out().model_dump()
    return result
