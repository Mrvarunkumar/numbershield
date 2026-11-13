"""
NumberShield - In-Memory Database Layer
All data lives in process memory. No external database required.
Data auto-purges after TTL_MINUTES of inactivity (default: 30 min).
Data also resets on every server restart.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("numbershield.db")

# Auto-cleanup interval: data resets after this many minutes of inactivity
TTL_MINUTES = 30


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


INITIAL_SERVICES = [
    {"id": 1, "name": "CampusConnect", "category": "Education", "note": "Synthetic demo service; no live integration."},
    {"id": 2, "name": "SocialSphere", "category": "Social media", "note": "Illustrative platform; not affiliated with a real company."},
    {"id": 3, "name": "ShopTrail", "category": "E-Commerce", "note": "Synthetic demo service; no live integration."},
    {"id": 4, "name": "CareerBridge", "category": "Recruitment", "note": "Synthetic demo service; no live integration."},
    {"id": 5, "name": "HealthTrack", "category": "Healthcare", "note": "Synthetic demo service; no live integration."},
    {"id": 6, "name": "BankSecure", "category": "Finance", "note": "Synthetic demo service; no live integration."},
]


def _initial_consents(stamp: str) -> List[Dict[str, Any]]:
    return [
        {"id": 1, "service_id": 1, "status": "allowed", "updated_at": stamp},
        {"id": 2, "service_id": 2, "status": "allowed", "updated_at": stamp},
        {"id": 3, "service_id": 3, "status": "denied", "updated_at": stamp},
        {"id": 4, "service_id": 4, "status": "withdrawn", "updated_at": stamp},
        {"id": 5, "service_id": 5, "status": "allowed", "updated_at": stamp},
        {"id": 6, "service_id": 6, "status": "withdrawn", "updated_at": stamp},
    ]


def _initial_exposures(stamp: str) -> List[Dict[str, Any]]:
    return [
        {"id": 1, "service_id": 1, "exposure_type": "Registration form", "severity": "low", "evidence": "Demo: number entered during university portal registration.", "created_at": stamp},
        {"id": 2, "service_id": 2, "exposure_type": "Account profile", "severity": "high", "evidence": "Demo: contact identifier publicly visible on profile page.", "created_at": stamp},
        {"id": 3, "service_id": 3, "exposure_type": "Marketing opt-in", "severity": "medium", "evidence": "Demo: marketing SMS preference list needs review.", "created_at": stamp},
        {"id": 4, "service_id": 4, "exposure_type": "Old account", "severity": "medium", "evidence": "Demo: historic disclosure noted from old job application.", "created_at": stamp},
        {"id": 5, "service_id": 5, "exposure_type": "Appointment system", "severity": "low", "evidence": "Demo: used for appointment reminders only.", "created_at": stamp},
        {"id": 6, "service_id": 6, "exposure_type": "Transaction alerts", "severity": "high", "evidence": "Demo: mobile banking alert destination visible in settings.", "created_at": stamp},
    ]


class MemoryDB:
    """
    In-memory data store. All data lives only in process memory.
    - Resets to demo seed data on server start.
    - Auto-purges user-generated data after TTL_MINUTES of inactivity.
    - No external dependencies whatsoever.
    """

    def __init__(self, ttl_minutes: int = TTL_MINUTES):
        self._ttl_seconds = ttl_minutes * 60
        self._last_activity = time.monotonic()
        self._lock = threading.Lock()
        self._cleanup_timer: Optional[threading.Timer] = None
        self.reset()
        self._schedule_cleanup()

    def _touch(self):
        """Update last-activity timestamp on every write operation."""
        self._last_activity = time.monotonic()

    def _schedule_cleanup(self):
        """Schedule auto-purge check after TTL expires."""
        if self._cleanup_timer is not None:
            self._cleanup_timer.cancel()
        self._cleanup_timer = threading.Timer(self._ttl_seconds, self._maybe_cleanup)
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()

    def _maybe_cleanup(self):
        """Reset data if no write activity occurred within the TTL window."""
        elapsed = time.monotonic() - self._last_activity
        if elapsed >= self._ttl_seconds:
            with self._lock:
                logger.info(
                    "Auto-cleanup: no activity for %d min. Resetting to demo data.",
                    self._ttl_seconds // 60,
                )
                self.reset()
        # Re-schedule for next check
        self._schedule_cleanup()

    def reset(self):
        stamp = now()
        self.services = [dict(s) for s in INITIAL_SERVICES]
        self.consents = _initial_consents(stamp)
        self.exposures = _initial_exposures(stamp)
        self.privacy_requests: List[Dict[str, Any]] = []
        self.audit_logs: List[Dict[str, Any]] = []
        self.next_req_id = 1
        self.next_audit_id = 1

    def reset_demo(self):
        with self._lock:
            self.reset()
            self._touch()

    # ── Services ─────────────────────────────────────────────────────

    def get_services(self) -> List[Dict[str, Any]]:
        return sorted(self.services, key=lambda s: s["id"])

    def get_service_by_id(self, sid: int) -> Optional[Dict[str, Any]]:
        for s in self.services:
            if s["id"] == sid:
                return dict(s)
        return None

    # ── Consents ─────────────────────────────────────────────────────

    def get_consents(self) -> List[Dict[str, Any]]:
        s_map = {s["id"]: s for s in self.services}
        out = []
        for c in self.consents:
            svc = s_map.get(c["service_id"], {})
            out.append({
                "id": c["id"],
                "service_id": c["service_id"],
                "service_name": svc.get("name", "Unknown"),
                "category": svc.get("category", "General"),
                "note": svc.get("note", ""),
                "status": c["status"],
                "updated_at": c["updated_at"],
            })
        return sorted(out, key=lambda x: x["id"])

    def update_consent(self, consent_id: int, status: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for c in self.consents:
                if c["id"] == consent_id:
                    s_map = {s["id"]: s for s in self.services}
                    svc = s_map.get(c["service_id"], {})
                    old_status = c["status"]
                    stamp = now()
                    c["status"] = status
                    c["updated_at"] = stamp
                    details = json.dumps({"service": svc.get("name"), "from": old_status, "to": status})
                    self._add_audit("consent_updated", "consent", consent_id, details, stamp)
                    self._touch()
                    return {"id": consent_id, "status": status, "updated_at": stamp}
        return None

    # ── Exposures ────────────────────────────────────────────────────

    def get_exposures(self, severity: Optional[str] = None, limit: int = 50, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        s_map = {s["id"]: s for s in self.services}
        all_items = []
        for e in self.exposures:
            svc = s_map.get(e["service_id"], {})
            item = dict(e)
            item["service_name"] = svc.get("name", "Unknown")
            all_items.append(item)
        total = len(all_items)
        if severity:
            filtered = [x for x in all_items if x["severity"] == severity]
        else:
            filtered = all_items
        return filtered[offset: offset + limit], total

    def get_all_exposures(self) -> List[Dict[str, Any]]:
        s_map = {s["id"]: s for s in self.services}
        out = []
        for e in self.exposures:
            item = dict(e)
            item["service_name"] = s_map.get(e["service_id"], {}).get("name", "Unknown")
            out.append(item)
        return out

    # ── Privacy Requests ─────────────────────────────────────────────

    def create_request(self, service_id: int, request_type: str, ref: str, text: str) -> Optional[Dict[str, Any]]:
        svc = self.get_service_by_id(service_id)
        if not svc:
            return None
        with self._lock:
            stamp = now()
            rid = self.next_req_id
            self.next_req_id += 1
            rec = {
                "id": rid,
                "service_id": service_id,
                "service_name": svc["name"],
                "request_type": request_type,
                "status": "draft",
                "reference": ref,
                "draft_text": text,
                "created_at": stamp,
            }
            self.privacy_requests.append(rec)
            details = json.dumps({"service": svc["name"], "type": request_type, "reference": ref})
            self._add_audit("privacy_request_drafted", "privacy_request", rid, details, stamp)
            self._touch()
            return rec

    def get_requests(self) -> List[Dict[str, Any]]:
        s_map = {s["id"]: s for s in self.services}
        out = []
        for r in self.privacy_requests:
            item = dict(r)
            item["service_name"] = s_map.get(r["service_id"], {}).get("name", item.get("service_name", "Unknown"))
            out.append(item)
        return sorted(out, key=lambda x: x["id"], reverse=True)

    # ── Audit Log ────────────────────────────────────────────────────

    def _add_audit(self, action: str, entity_type: str, entity_id: int, details: str, stamp: str):
        """Internal: call only while holding self._lock."""
        aid = self.next_audit_id
        self.next_audit_id += 1
        self.audit_logs.append({
            "id": aid,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "details": details,
            "created_at": stamp,
        })

    def get_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        return sorted(self.audit_logs, key=lambda x: x["id"], reverse=True)[:limit]

    # ── Summary ──────────────────────────────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for c in self.consents:
            st = c["status"]
            counts[st] = counts.get(st, 0) + 1
        drafts = sum(1 for r in self.privacy_requests if r.get("status") == "draft")
        return {
            "services": len(self.services),
            "counts": counts,
            "exposures": self.get_all_exposures(),
            "drafts": drafts,
            "total_requests": len(self.privacy_requests),
            "audit_count": len(self.audit_logs),
        }


# ── Singleton ────────────────────────────────────────────────────────

_DB_INSTANCE: Optional[MemoryDB] = None


def get_db() -> MemoryDB:
    global _DB_INSTANCE
    if _DB_INSTANCE is None:
        _DB_INSTANCE = MemoryDB(ttl_minutes=TTL_MINUTES)
        logger.info(
            "In-memory DB initialized. Data auto-resets after %d min of inactivity or on server restart.",
            TTL_MINUTES,
        )
    return _DB_INSTANCE


def get_db_mode() -> str:
    return "memory"

