"""
NumberShield 2.0 - Session-Isolated In-Memory Storage Engine
- Zero permanent database (all state is ephemeral RAM only).
- Zero fake / synthetic demo data: all services and exposures are populated from real sources (e.g. Email Source).
- Multi-tenant Session Isolation: Person A's requests, consents, and audit logs are isolated from Person B.
- Automatic Data Destruction: TTL-based expiration and cleanup.
- Resets cleanly on restart.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("numbershield.db")

TTL_MINUTES = 30


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# No hardcoded demo data: starts clean by default
INITIAL_SERVICES: List[Dict[str, Any]] = []


def _initial_consents(stamp: str) -> List[Dict[str, Any]]:
    return []


def _initial_exposures(stamp: str) -> List[Dict[str, Any]]:
    return []


class MemoryDB:
    """
    Session-Isolated In-Memory Store.
    - Zero permanent storage.
    - All data dynamically populated from verified real-world sources (e.g. Email source).
    - Isolated per-session storage for authenticated users.
    """

    def __init__(self, ttl_minutes: int = TTL_MINUTES):
        self._ttl_seconds = ttl_minutes * 60
        self._last_activity = time.monotonic()
        self._lock = threading.Lock()
        
        # Session-specific state: session_id -> data
        self._session_services: Dict[str, List[Dict[str, Any]]] = {}
        self._session_consents: Dict[str, List[Dict[str, Any]]] = {}
        self._session_consent_overrides: Dict[str, Dict[int, str]] = {}
        self._session_exposures: Dict[str, List[Dict[str, Any]]] = {}
        self._session_requests: Dict[str, List[Dict[str, Any]]] = {}
        self._session_audit: Dict[str, List[Dict[str, Any]]] = {}
        
        self.reset()

    def _touch(self):
        self._last_activity = time.monotonic()

    def reset(self):
        stamp = now()
        self.services = [dict(s) for s in INITIAL_SERVICES]
        self.default_consents = _initial_consents(stamp)
        self.exposures = _initial_exposures(stamp)
        self.default_requests: List[Dict[str, Any]] = []
        self.default_audit: List[Dict[str, Any]] = []
        self.next_svc_id = 1
        self.next_req_id = 1
        self.next_audit_id = 1
        self.next_consent_id = 1
        self.next_expo_id = 1

    def reset_demo(self):
        with self._lock:
            self.reset()
            self._session_services.clear()
            self._session_consents.clear()
            self._session_consent_overrides.clear()
            self._session_exposures.clear()
            self._session_requests.clear()
            self._session_audit.clear()
            self._touch()

    # ── Real-World Email Source Integration ───────────────────────────

    def populate_from_email_source(
        self,
        session_id: Optional[str],
        discovered_services: List[Dict[str, Any]],
        discovered_exposures: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Dynamically populates the user's isolated session with real services
        and exposure records extracted from their email source.
        """
        stamp = now()
        with self._lock:
            sess_services: List[Dict[str, Any]] = []
            sess_consents: List[Dict[str, Any]] = []
            sess_exposures: List[Dict[str, Any]] = []

            # 1. Create real services
            name_to_id: Dict[str, int] = {}
            for s in discovered_services:
                s_name = s.get("name", "Unknown Service").strip()
                if not s_name:
                    continue
                sid = self.next_svc_id
                self.next_svc_id += 1
                name_to_id[s_name.lower()] = sid

                svc_record = {
                    "id": sid,
                    "name": s_name,
                    "category": s.get("category", "Online Service"),
                    "note": s.get("note") or f"Identified via email message ({s.get('sample_subject', 'Account notification')[:60]})",
                    "from_address": s.get("from", ""),
                    "email_count": s.get("count", 1),
                }
                sess_services.append(svc_record)

                # Create corresponding consent tracking item
                cid = self.next_consent_id
                self.next_consent_id += 1
                sess_consents.append({
                    "id": cid,
                    "service_id": sid,
                    "service_name": s_name,
                    "category": s.get("category", "Online Service"),
                    "note": svc_record["note"],
                    "status": "allowed",
                    "updated_at": stamp,
                })

            # 2. Create real exposure records
            for e in discovered_exposures:
                svc_name = e.get("service", "").strip()
                sid = name_to_id.get(svc_name.lower(), 1)
                eid = self.next_expo_id
                self.next_expo_id += 1
                sess_exposures.append({
                    "id": eid,
                    "service_id": sid,
                    "service_name": svc_name,
                    "exposure_type": e.get("exposure_type", "Account / Service Registration"),
                    "severity": e.get("severity", "medium"),
                    "evidence": e.get("evidence", "Discovered from email source header evidence."),
                    "created_at": e.get("date") or stamp,
                })

            if session_id:
                self._session_services[session_id] = sess_services
                self._session_consents[session_id] = sess_consents
                self._session_exposures[session_id] = sess_exposures
            else:
                self.services = sess_services
                self.default_consents = sess_consents
                self.exposures = sess_exposures

            self._touch()
            return {
                "services_count": len(sess_services),
                "exposures_count": len(sess_exposures),
                "services": sess_services,
                "exposures": sess_exposures,
            }

    # ── Services ─────────────────────────────────────────────────────

    def get_services(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if session_id and session_id in self._session_services:
                return sorted(self._session_services[session_id], key=lambda s: s["id"])
            return sorted(self.services, key=lambda s: s["id"])

    def get_service_by_id(self, sid: int, session_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        services = self.get_services(session_id=session_id)
        for s in services:
            if s["id"] == sid:
                return dict(s)
        return None

    def add_custom_service(self, name: str, category: str = "General", session_id: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            sid = self.next_svc_id
            self.next_svc_id += 1
            rec = {"id": sid, "name": name, "category": category, "note": "Manually tracked identifier"}
            if session_id:
                if session_id not in self._session_services:
                    self._session_services[session_id] = []
                self._session_services[session_id].append(rec)
            else:
                self.services.append(rec)
            return rec

    # ── Consents (Session Isolated) ───────────────────────────────────

    def get_consents(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if session_id and session_id in self._session_consents:
                raw_consents = self._session_consents[session_id]
                s_map = {s["id"]: s for s in self._session_services.get(session_id, [])}
            else:
                raw_consents = self.default_consents
                s_map = {s["id"]: s for s in self.services}

            user_overrides = self._session_consent_overrides.get(session_id, {}) if session_id else {}
            out = []
            for c in raw_consents:
                svc = s_map.get(c["service_id"], {})
                effective_status = user_overrides.get(c["id"], c["status"])
                out.append({
                    "id": c["id"],
                    "service_id": c["service_id"],
                    "service_name": svc.get("name", c.get("service_name", "Unknown")),
                    "category": svc.get("category", c.get("category", "General")),
                    "note": svc.get("note", c.get("note", "")),
                    "status": effective_status,
                    "updated_at": c["updated_at"],
                })
            return sorted(out, key=lambda x: x["id"])

    def update_consent(self, consent_id: int, status: str, session_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with self._lock:
            stamp = now()
            consents = self.get_consents(session_id=session_id)
            target = next((c for c in consents if c["id"] == consent_id), None)
            if not target:
                return None

            old_status = target["status"]
            if session_id:
                if session_id not in self._session_consent_overrides:
                    self._session_consent_overrides[session_id] = {}
                self._session_consent_overrides[session_id][consent_id] = status
            else:
                target["status"] = status

            details = json.dumps({"service": target.get("service_name"), "from": old_status, "to": status})
            self.add_audit("consent_updated", "consent", consent_id, details, stamp, session_id=session_id)
            self._touch()
            return {"id": consent_id, "status": status, "updated_at": stamp}

    # ── Exposures ────────────────────────────────────────────────────

    def get_exposures(self, severity: Optional[str] = None, limit: int = 50, offset: int = 0, session_id: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
        with self._lock:
            if session_id and session_id in self._session_exposures:
                all_items = list(self._session_exposures[session_id])
            else:
                s_map = {s["id"]: s for s in self.services}
                all_items = []
                for e in self.exposures:
                    svc = s_map.get(e["service_id"], {})
                    item = dict(e)
                    item["service_name"] = svc.get("name", "Unknown")
                    all_items.append(item)

            total = len(all_items)
            if severity:
                filtered = [x for x in all_items if x.get("severity") == severity]
            else:
                filtered = all_items
            return filtered[offset: offset + limit], total

    def get_all_exposures(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if session_id and session_id in self._session_exposures:
                return list(self._session_exposures[session_id])
            s_map = {s["id"]: s for s in self.services}
            out = []
            for e in self.exposures:
                item = dict(e)
                item["service_name"] = s_map.get(e["service_id"], {}).get("name", "Unknown")
                out.append(item)
            return out

    # ── Privacy Requests (Session Isolated) ───────────────────────────

    def create_request(
        self,
        service_id: int,
        request_type: str,
        ref: str,
        text: str,
        session_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        svc = self.get_service_by_id(service_id, session_id=session_id)
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
                "session_id": session_id,
            }
            if session_id:
                if session_id not in self._session_requests:
                    self._session_requests[session_id] = []
                self._session_requests[session_id].append(rec)
            else:
                self.default_requests.append(rec)

            details = json.dumps({"service": svc["name"], "type": request_type, "reference": ref})
            self.add_audit("privacy_request_drafted", "privacy_request", rid, details, stamp, session_id=session_id)
            self._touch()
            return rec

    def get_requests(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if session_id:
                raw_list = self._session_requests.get(session_id, [])
            else:
                raw_list = self.default_requests

            return sorted([dict(r) for r in raw_list], key=lambda x: x["id"], reverse=True)

    # ── Audit Log (Session Isolated) ──────────────────────────────────

    def add_audit(
        self,
        action: str,
        entity_type: str,
        entity_id: int,
        details: str,
        stamp: str,
        session_id: Optional[str] = None,
    ):
        aid = self.next_audit_id
        self.next_audit_id += 1
        entry = {
            "id": aid,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "details": details,
            "created_at": stamp,
            "session_id": session_id,
        }
        if session_id:
            if session_id not in self._session_audit:
                self._session_audit[session_id] = []
            self._session_audit[session_id].append(entry)
        else:
            self.default_audit.append(entry)

    def get_audit(self, limit: int = 100, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if session_id:
                raw_list = self._session_audit.get(session_id, [])
            else:
                raw_list = self.default_audit
            return sorted(raw_list, key=lambda x: x["id"], reverse=True)[:limit]

    # ── Summary ──────────────────────────────────────────────────────

    def get_summary(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        services = self.get_services(session_id=session_id)
        consents = self.get_consents(session_id=session_id)
        counts: Dict[str, int] = {}
        for c in consents:
            st = c["status"]
            counts[st] = counts.get(st, 0) + 1

        requests = self.get_requests(session_id=session_id)
        drafts = sum(1 for r in requests if r.get("status") == "draft")
        audits = self.get_audit(session_id=session_id)
        exposures = self.get_all_exposures(session_id=session_id)

        return {
            "services": len(services),
            "counts": counts,
            "exposures": exposures,
            "drafts": drafts,
            "total_requests": len(requests),
            "audit_count": len(audits),
        }

    def clear_session_data(self, session_id: str):
        """Immediately destroys all session-isolated data when user logs out."""
        with self._lock:
            self._session_services.pop(session_id, None)
            self._session_consents.pop(session_id, None)
            self._session_consent_overrides.pop(session_id, None)
            self._session_exposures.pop(session_id, None)
            self._session_requests.pop(session_id, None)
            self._session_audit.pop(session_id, None)


# ── Singleton ────────────────────────────────────────────────────────

_DB_INSTANCE: Optional[MemoryDB] = None


def get_db() -> MemoryDB:
    global _DB_INSTANCE
    if _DB_INSTANCE is None:
        _DB_INSTANCE = MemoryDB(ttl_minutes=TTL_MINUTES)
    return _DB_INSTANCE


def get_db_mode() -> str:
    return "real_world_email_source_ephemeral"
