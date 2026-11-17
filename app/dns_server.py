"""Authoritative UDP DNS service for the fixed intranet zone.

Every answer is built from one immutable version snapshot fetched in a
single storage read, so a reply can never mix records of two versions.
While a transfer is in progress the old version stays active and keeps
being answered.

Forensic evidence (``app/evidence.py``) is recorded from the *same*
snapshot tuple that built the reply and only handed to a bounded,
non-blocking queue: a burst or an unwritable evidence DB never delays or
fails resolution.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Tuple

from dnslib import A, DNSRecord, RR, QTYPE, RCODE
from dnslib.server import BaseResolver, DNSServer

from .config import settings
from .evidence import QueryEvidence, evidence_log, utc_iso
from .storage import storage

log = logging.getLogger("dns")


def _normalise(qname: str) -> str:
    return qname.rstrip(".").lower()


def _rcode_name(code: int) -> str:
    try:
        return str(RCODE[code])
    except Exception:  # pragma: no cover - unknown numeric rcode
        return str(code)


class ZoneResolver(BaseResolver):
    """Resolve in-zone A queries and record evidence for each reply."""

    def __init__(self) -> None:
        # Last immutable snapshot that was read successfully. Used only if
        # the zone DB is momentarily unreadable (e.g. an external writer
        # holds an exclusive lock), so UDP resolution stays available and
        # keeps answering the last known complete version.
        self._last_good: Tuple[int, List[Dict[str, str]]] | None = None

    def _snapshot(self) -> Tuple[int, List[Dict[str, str]]] | None:
        try:
            serial, records, _ = storage.get_active_version(fast=True)
            self._last_good = (serial, records)
            return serial, records
        except Exception as exc:
            if self._last_good is not None:
                log.warning("zone DB read failed (%s); serving last good "
                            "snapshot serial=%s", exc, self._last_good[0])
                return self._last_good
            log.error("zone DB read failed and no snapshot cached: %s", exc)
            return None

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        reply = request.reply()
        q = request.q
        qname = _normalise(str(q.qname))
        zone = settings.dns_zone.rstrip(".").lower()
        qtype_name = str(QTYPE[q.qtype])
        client_ip = self._client_ip(handler)

        in_zone = qname == zone or qname.endswith("." + zone)
        if not in_zone:
            # This service is authoritative only for the fixed zone.
            reply.header.rcode = RCODE.REFUSED
            return reply

        if qtype_name != "A":
            # In-zone but not an A query: authoritative NOERROR/NODATA.
            # (Forensic evidence covers A queries, which have a zone serial.)
            reply.header.rcode = RCODE.NOERROR
            return reply

        # One consistent read of pointer + version row -> one snapshot.
        # This exact tuple builds both the UDP reply and its evidence.
        snapshot = self._snapshot()
        if snapshot is None:
            # No snapshot ever read and the zone DB is unreadable: be
            # explicit rather than fabricate an NXDOMAIN. serial -1 means
            # "no zone snapshot existed for this answer" in the evidence.
            reply.header.rcode = RCODE.SERVFAIL
            self._record(client_ip, qname, qtype_name, reply, -1)
            return reply
        serial, records = snapshot
        name_map = {}
        for rec in records:
            name_map.setdefault(rec["name"], []).append(rec["ip"])

        ips: List[str] = name_map.get(qname, [])
        if not ips:
            reply.header.rcode = RCODE.NXDOMAIN
            log.debug("NXDOMAIN %s (serial=%s)", qname, serial)
            self._record(client_ip, qname, qtype_name, reply, serial)
            return reply

        for ip in ips:
            reply.add_answer(
                RR(
                    q.qname,
                    QTYPE.A,
                    rdata=A(ip),
                    ttl=30,
                )
            )
        log.debug("ANSWER %s -> %s (serial=%s)", qname, ips, serial)
        self._record(client_ip, qname, qtype_name, reply, serial)
        return reply

    @staticmethod
    def _client_ip(handler) -> str:
        try:
            return str(handler.client_address[0])
        except Exception:  # pragma: no cover - defensive
            return "unknown"

    @staticmethod
    def _record(client_ip: str, qname: str, qtype_name: str,
                reply: DNSRecord, serial: int) -> None:
        # Addresses are taken from the reply that is actually sent, so the
        # evidence can never claim an answer the client did not get.
        addresses = [str(rr.rdata) for rr in reply.rr]
        try:
            evidence_log.record(
                QueryEvidence(
                    at=utc_iso(),
                    client_ip=client_ip,
                    qname=qname,
                    qtype=qtype_name,
                    rcode=_rcode_name(reply.header.rcode),
                    addresses=addresses,
                    serial=serial,
                    role=settings.role,
                )
            )
        except Exception:  # pragma: no cover - evidence must never fail DNS
            log.exception("failed to enqueue evidence")


class DnsService:
    def __init__(self) -> None:
        self._server: DNSServer | None = None

    def start(self) -> None:
        resolver = ZoneResolver()
        # DNSServer is itself a daemon thread; start_thread() runs the
        # UDP serve loop without blocking the FastAPI startup.
        self._server = DNSServer(
            resolver,
            port=settings.dns_port,
            address=settings.dns_host,
            tcp=False,
        )
        self._server.start_thread()
        log.info(
            "UDP DNS listener on %s:%s (zone=%s, role=%s)",
            settings.dns_host,
            settings.dns_port,
            settings.dns_zone,
            settings.role,
        )

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.stop()
            except Exception:  # pragma: no cover
                pass


dns_service = DnsService()
