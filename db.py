"""
NumberShield - Database Layer (Supabase PostgreSQL / Supabase Client)
Replaces SQLite with Supabase cloud database.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv()
load_dotenv(ROOT / ".env")
load_dotenv(Path(__file__).resolve().parent / ".env")

logger = logging.getLogger("numbershield.db")

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

def initial_consents(stamp: str) -> List[Dict[str, Any]]:
    return [
        {"id": 1, "service_id": 1, "status": "allowed", "updated_at": stamp},
        {"id": 2, "service_id": 2, "status": "allowed", "updated_at": stamp},
        {"id": 3, "service_id": 3, "status": "denied", "updated_at": stamp},
        {"id": 4, "service_id": 4, "status": "withdrawn", "updated_at": stamp},
        {"id": 5, "service_id": 5, "status": "allowed", "updated_at": stamp},
        {"id": 6, "service_id": 6, "status": "withdrawn", "updated_at": stamp},
    ]

def initial_exposures(stamp: str) -> List[Dict[str, Any]]:
    return [
        {"id": 1, "service_id": 1, "exposure_type": "Registration form", "severity": "low", "evidence": "Demo: number entered during university portal registration.", "created_at": stamp},
        {"id": 2, "service_id": 2, "exposure_type": "Account profile", "severity": "high", "evidence": "Demo: contact identifier publicly visible on profile page.", "created_at": stamp},
        {"id": 3, "service_id": 3, "exposure_type": "Marketing opt-in", "severity": "medium", "evidence": "Demo: marketing SMS preference list needs review.", "created_at": stamp},
        {"id": 4, "service_id": 4, "exposure_type": "Old account", "severity": "medium", "evidence": "Demo: historic disclosure noted from old job application.", "created_at": stamp},
        {"id": 5, "service_id": 5, "exposure_type": "Appointment system", "severity": "low", "evidence": "Demo: used for appointment reminders only.", "created_at": stamp},
        {"id": 6, "service_id": 6, "exposure_type": "Transaction alerts", "severity": "high", "evidence": "Demo: mobile banking alert destination visible in settings.", "created_at": stamp},
    ]


class MemoryDB:
    """In-memory store used when Supabase credentials are not configured yet."""

    def __init__(self):
        self.reset()

    def reset(self):
        stamp = now()
        self.services = [dict(s) for s in INITIAL_SERVICES]
        self.consents = initial_consents(stamp)
        self.exposures = initial_exposures(stamp)
        self.privacy_requests: List[Dict[str, Any]] = []
        self.audit_logs: List[Dict[str, Any]] = []
        self.next_req_id = 1
        self.next_audit_id = 1

    def reset_demo(self):
        self.reset()


    def get_services(self) -> List[Dict[str, Any]]:
        return sorted(self.services, key=lambda s: s["id"])

    def get_service_by_id(self, sid: int) -> Optional[Dict[str, Any]]:
        for s in self.services:
            if s["id"] == sid:
                return dict(s)
        return None

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
        for c in self.consents:
            if c["id"] == consent_id:
                s_map = {s["id"]: s for s in self.services}
                svc = s_map.get(c["service_id"], {})
                old_status = c["status"]
                stamp = now()
                c["status"] = status
                c["updated_at"] = stamp
                details = json.dumps({"service": svc.get("name"), "from": old_status, "to": status})
                self.add_audit("consent_updated", "consent", consent_id, details, stamp)
                return {"id": consent_id, "status": status, "updated_at": stamp}
        return None

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
        return filtered[offset : offset + limit], total

    def get_all_exposures(self) -> List[Dict[str, Any]]:
        s_map = {s["id"]: s for s in self.services}
        out = []
        for e in self.exposures:
            item = dict(e)
            item["service_name"] = s_map.get(e["service_id"], {}).get("name", "Unknown")
            out.append(item)
        return out

    def create_request(self, service_id: int, request_type: str, ref: str, text: str) -> Optional[Dict[str, Any]]:
        svc = self.get_service_by_id(service_id)
        if not svc:
            return None
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
        self.add_audit("privacy_request_drafted", "privacy_request", rid, details, stamp)
        return rec

    def get_requests(self) -> List[Dict[str, Any]]:
        s_map = {s["id"]: s for s in self.services}
        out = []
        for r in self.privacy_requests:
            item = dict(r)
            item["service_name"] = s_map.get(r["service_id"], {}).get("name", item.get("service_name", "Unknown"))
            out.append(item)
        return sorted(out, key=lambda x: x["id"], reverse=True)

    def add_audit(self, action: str, entity_type: str, entity_id: int, details: str, stamp: str):
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


class SupabaseClientDB:
    """Live database client backed by Supabase PostgREST REST API."""

    def __init__(self, client):
        self.client = client

    def get_services(self) -> List[Dict[str, Any]]:
        res = self.client.table("services").select("*").order("id").execute()
        return res.data or []

    def get_service_by_id(self, sid: int) -> Optional[Dict[str, Any]]:
        res = self.client.table("services").select("*").eq("id", sid).limit(1).execute()
        return res.data[0] if res.data else None

    def get_consents(self) -> List[Dict[str, Any]]:
        res = self.client.table("consents").select("id, service_id, status, updated_at, services(name, category, note)").order("id").execute()
        out = []
        for r in (res.data or []):
            svc = r.get("services") or {}
            out.append({
                "id": r["id"],
                "service_id": r["service_id"],
                "service_name": svc.get("name", "Unknown"),
                "category": svc.get("category", "General"),
                "note": svc.get("note", ""),
                "status": r["status"],
                "updated_at": str(r.get("updated_at", "")),
            })
        return out

    def update_consent(self, consent_id: int, status: str) -> Optional[Dict[str, Any]]:
        c_res = self.client.table("consents").select("*, services(name)").eq("id", consent_id).limit(1).execute()
        if not c_res.data:
            return None
        current = c_res.data[0]
        svc = current.get("services") or {}
        old_status = current.get("status")
        stamp = now()

        self.client.table("consents").update({"status": status, "updated_at": stamp}).eq("id", consent_id).execute()
        details = json.dumps({"service": svc.get("name", "Unknown"), "from": old_status, "to": status})
        self.add_audit("consent_updated", "consent", consent_id, details, stamp)
        return {"id": consent_id, "status": status, "updated_at": stamp}

    def get_exposures(self, severity: Optional[str] = None, limit: int = 50, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        all_res = self.client.table("exposures").select("id, service_id, exposure_type, severity, evidence, created_at, services(name)").order("id").execute()
        all_items = []
        for r in (all_res.data or []):
            svc = r.get("services") or {}
            all_items.append({
                "id": r["id"],
                "service_id": r["service_id"],
                "service_name": svc.get("name", "Unknown"),
                "exposure_type": r["exposure_type"],
                "severity": r["severity"],
                "evidence": r["evidence"],
                "created_at": str(r.get("created_at", "")),
            })
        total = len(all_items)
        if severity:
            filtered = [x for x in all_items if x["severity"] == severity]
        else:
            filtered = all_items
        return filtered[offset : offset + limit], total

    def get_all_exposures(self) -> List[Dict[str, Any]]:
        res = self.client.table("exposures").select("id, service_id, exposure_type, severity, evidence, created_at, services(name)").order("id").execute()
        out = []
        for r in (res.data or []):
            svc = r.get("services") or {}
            out.append({
                "id": r["id"],
                "service_id": r["service_id"],
                "service_name": svc.get("name", "Unknown"),
                "exposure_type": r["exposure_type"],
                "severity": r["severity"],
                "evidence": r["evidence"],
                "created_at": str(r.get("created_at", "")),
            })
        return out

    def create_request(self, service_id: int, request_type: str, ref: str, text: str) -> Optional[Dict[str, Any]]:
        svc = self.get_service_by_id(service_id)
        if not svc:
            return None
        stamp = now()
        res = self.client.table("privacy_requests").insert({
            "service_id": service_id,
            "request_type": request_type,
            "status": "draft",
            "reference": ref,
            "draft_text": text,
            "created_at": stamp,
        }).execute()
        if not res.data:
            return None
        created = res.data[0]
        rid = created["id"]
        details = json.dumps({"service": svc["name"], "type": request_type, "reference": ref})
        self.add_audit("privacy_request_drafted", "privacy_request", rid, details, stamp)
        return {
            "id": rid,
            "service_id": service_id,
            "service_name": svc["name"],
            "request_type": request_type,
            "status": "draft",
            "reference": ref,
            "draft_text": text,
            "created_at": stamp,
        }

    def get_requests(self) -> List[Dict[str, Any]]:
        res = self.client.table("privacy_requests").select("id, service_id, request_type, status, reference, draft_text, created_at, services(name)").order("id", desc=True).execute()
        out = []
        for r in (res.data or []):
            svc = r.get("services") or {}
            out.append({
                "id": r["id"],
                "service_id": r["service_id"],
                "service_name": svc.get("name", "Unknown"),
                "request_type": r["request_type"],
                "status": r["status"],
                "reference": r["reference"],
                "draft_text": r["draft_text"],
                "created_at": str(r.get("created_at", "")),
            })
        return out

    def add_audit(self, action: str, entity_type: str, entity_id: int, details: str, stamp: str):
        self.client.table("audit_logs").insert({
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "details": details,
            "created_at": stamp,
        }).execute()

    def get_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        res = self.client.table("audit_logs").select("*").order("id", desc=True).limit(limit).execute()
        return res.data or []

    def get_summary(self) -> Dict[str, Any]:
        services = self.get_services()
        consents_res = self.client.table("consents").select("status").execute()
        counts: Dict[str, int] = {}
        for c in (consents_res.data or []):
            st = c.get("status", "")
            counts[st] = counts.get(st, 0) + 1

        exposures = self.get_all_exposures()
        drafts_res = self.client.table("privacy_requests").select("id", count="exact").eq("status", "draft").execute()
        drafts_count = drafts_res.count if hasattr(drafts_res, "count") and drafts_res.count is not None else len(drafts_res.data or [])
        total_reqs_res = self.client.table("privacy_requests").select("id", count="exact").execute()
        total_reqs = total_reqs_res.count if hasattr(total_reqs_res, "count") and total_reqs_res.count is not None else len(total_reqs_res.data or [])
        audit_res = self.client.table("audit_logs").select("id", count="exact").execute()
        audit_count = audit_res.count if hasattr(audit_res, "count") and audit_res.count is not None else len(audit_res.data or [])

        return {
            "services": len(services),
            "counts": counts,
            "exposures": exposures,
            "drafts": drafts_count,
            "total_requests": total_reqs,
            "audit_count": audit_count,
        }

    def reset_demo(self):
        stamp = now()
        try:
            self.client.table("audit_logs").delete().neq("id", 0).execute()
            self.client.table("privacy_requests").delete().neq("id", 0).execute()
            self.client.table("exposures").delete().neq("id", 0).execute()
            self.client.table("consents").delete().neq("id", 0).execute()
            self.client.table("services").delete().neq("id", 0).execute()
        except Exception as e:
            logger.warning(f"Error while resetting Supabase tables: {e}")

        # Re-seed
        self.client.table("services").upsert(INITIAL_SERVICES).execute()
        self.client.table("consents").upsert(initial_consents(stamp)).execute()
        self.client.table("exposures").upsert(initial_exposures(stamp)).execute()


class SupabasePostgresDB:
    """Direct PostgreSQL connection to Supabase via psycopg2."""

    def __init__(self, dsn: str):
        self.dsn = dsn
        self._ensure_schema()

    def _get_conn(self):
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = psycopg2.connect(self.dsn, cursor_factory=RealDictCursor)
        conn.autocommit = True
        return conn

    def _ensure_schema(self):
        schema_file = Path(__file__).resolve().parent.parent / "supabase_schema.sql"
        if schema_file.exists():
            sql = schema_file.read_text(encoding="utf-8")
            try:
                with self._get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(sql)
            except Exception as e:
                logger.warning(f"Could not automatically run schema script on PostgreSQL: {e}")

    def get_services(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM public.services ORDER BY id")
                return [dict(r) for r in cur.fetchall()]

    def get_service_by_id(self, sid: int) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM public.services WHERE id = %s", (sid,))
                row = cur.fetchone()
                return dict(row) if row else None

    def get_consents(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT c.id, c.service_id, s.name service_name, s.category, s.note, c.status, c.updated_at "
                    "FROM public.consents c JOIN public.services s ON s.id = c.service_id ORDER BY c.id"
                )
                return [dict(r) for r in cur.fetchall()]

    def update_consent(self, consent_id: int, status: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT c.*, s.name FROM public.consents c JOIN public.services s ON s.id = c.service_id WHERE c.id = %s",
                    (consent_id,)
                )
                row = cur.fetchone()
                if not row:
                    return None
                stamp = now()
                cur.execute("UPDATE public.consents SET status = %s, updated_at = %s WHERE id = %s", (status, stamp, consent_id))
                details = json.dumps({"service": row["name"], "from": row["status"], "to": status})
                cur.execute(
                    "INSERT INTO public.audit_logs(action, entity_type, entity_id, details, created_at) VALUES (%s, %s, %s, %s, %s)",
                    ("consent_updated", "consent", consent_id, details, stamp)
                )
                return {"id": consent_id, "status": status, "updated_at": stamp}

    def get_exposures(self, severity: Optional[str] = None, limit: int = 50, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                base = "SELECT e.*, s.name service_name FROM public.exposures e JOIN public.services s ON s.id = e.service_id"
                params = []
                if severity:
                    base += " WHERE e.severity = %s"
                    params.append(severity)
                base += " ORDER BY e.id LIMIT %s OFFSET %s"
                params.extend([limit, offset])
                cur.execute(base, tuple(params))
                items = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT COUNT(*) AS n FROM public.exposures")
                total = cur.fetchone()["n"]
                return items, total

    def get_all_exposures(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT e.*, s.name service_name FROM public.exposures e JOIN public.services s ON s.id = e.service_id")
                return [dict(r) for r in cur.fetchall()]

    def create_request(self, service_id: int, request_type: str, ref: str, text: str) -> Optional[Dict[str, Any]]:
        svc = self.get_service_by_id(service_id)
        if not svc:
            return None
        stamp = now()
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO public.privacy_requests (service_id, request_type, status, reference, draft_text, created_at) "
                    "VALUES (%s, %s, 'draft', %s, %s, %s) RETURNING id",
                    (service_id, request_type, ref, text, stamp)
                )
                rid = cur.fetchone()["id"]
                details = json.dumps({"service": svc["name"], "type": request_type, "reference": ref})
                cur.execute(
                    "INSERT INTO public.audit_logs(action, entity_type, entity_id, details, created_at) VALUES (%s, %s, %s, %s, %s)",
                    ("privacy_request_drafted", "privacy_request", rid, details, stamp)
                )
                return {
                    "id": rid,
                    "service_id": service_id,
                    "service_name": svc["name"],
                    "request_type": request_type,
                    "status": "draft",
                    "reference": ref,
                    "draft_text": text,
                    "created_at": stamp,
                }

    def get_requests(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT r.*, s.name service_name FROM public.privacy_requests r JOIN public.services s ON s.id = r.service_id ORDER BY r.id DESC"
                )
                return [dict(r) for r in cur.fetchall()]

    def get_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM public.audit_logs ORDER BY id DESC LIMIT %s", (limit,))
                return [dict(r) for r in cur.fetchall()]

    def get_summary(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM public.services")
                services_count = cur.fetchone()["n"]

                cur.execute("SELECT status, COUNT(*) AS n FROM public.consents GROUP BY status")
                counts = {r["status"]: r["n"] for r in cur.fetchall()}

                cur.execute("SELECT e.*, s.name service_name FROM public.exposures e JOIN public.services s ON s.id = e.service_id")
                exposures = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT COUNT(*) AS n FROM public.privacy_requests WHERE status = 'draft'")
                drafts = cur.fetchone()["n"]

                cur.execute("SELECT COUNT(*) AS n FROM public.privacy_requests")
                total_reqs = cur.fetchone()["n"]

                cur.execute("SELECT COUNT(*) AS n FROM public.audit_logs")
                audit_count = cur.fetchone()["n"]

                return {
                    "services": services_count,
                    "counts": counts,
                    "exposures": exposures,
                    "drafts": drafts,
                    "total_requests": total_reqs,
                    "audit_count": audit_count,
                }

    def reset_demo(self):
        stamp = now()
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                for table in ("audit_logs", "privacy_requests", "exposures", "consents", "services"):
                    cur.execute(f"TRUNCATE TABLE public.{table} RESTART IDENTITY CASCADE")

                for s in INITIAL_SERVICES:
                    cur.execute(
                        "INSERT INTO public.services(id, name, category, note) VALUES (%s, %s, %s, %s)",
                        (s["id"], s["name"], s["category"], s["note"])
                    )
                for c in initial_consents(stamp):
                    cur.execute(
                        "INSERT INTO public.consents(id, service_id, status, updated_at) VALUES (%s, %s, %s, %s)",
                        (c["id"], c["service_id"], c["status"], c["updated_at"])
                    )
                for e in initial_exposures(stamp):
                    cur.execute(
                        "INSERT INTO public.exposures(id, service_id, exposure_type, severity, evidence, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
                        (e["id"], e["service_id"], e["exposure_type"], e["severity"], e["evidence"], e["created_at"])
                    )


_DB_INSTANCE = None
_DB_MODE = "memory"

def get_db():
    global _DB_INSTANCE, _DB_MODE
    if _DB_INSTANCE is not None:
        return _DB_INSTANCE

    # Priority 1: Supabase Direct Postgres Connection
    db_url = (os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL") or "").strip()
    if db_url and not "your-db-password" in db_url:
        try:
            _DB_INSTANCE = SupabasePostgresDB(db_url)
            _DB_MODE = "supabase_postgres"
            logger.info("Connected to Supabase PostgreSQL database.")
            return _DB_INSTANCE
        except Exception as exc:
            logger.warning(f"Could not connect via direct PostgreSQL ({exc}); falling back to Supabase client.")

    # Priority 2: Supabase Client (REST API)
    supabase_url = os.getenv("SUPABASE_URL", "").strip()
    supabase_key = os.getenv("SUPABASE_KEY", "").strip() or os.getenv("SUPABASE_ANON_KEY", "").strip()
    is_valid_url = supabase_url.startswith("http") and "your-project-id" not in supabase_url
    is_valid_key = bool(supabase_key) and "your-supabase-anon" not in supabase_key

    if is_valid_url and is_valid_key:
        try:
            from supabase import create_client
            client = create_client(supabase_url, supabase_key)
            # Test connectivity
            client.table("services").select("id").limit(1).execute()
            _DB_INSTANCE = SupabaseClientDB(client)
            _DB_MODE = "supabase_client"
            logger.info(f"Connected to Supabase Cloud API ({supabase_url}).")
            return _DB_INSTANCE
        except Exception as exc:
            logger.warning(f"Could not connect via Supabase client ({exc}); falling back to memory store.")

    # Fallback: In-memory store
    _DB_INSTANCE = MemoryDB()
    _DB_MODE = "memory"
    logger.info("Operating in in-memory mode. Add SUPABASE_URL and SUPABASE_KEY to .env to connect live Supabase.")
    return _DB_INSTANCE

def get_db_mode() -> str:
    global _DB_INSTANCE, _DB_MODE
    if _DB_INSTANCE is None:
        get_db()
    return _DB_MODE
