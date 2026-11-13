"""
NumberShield 2.0 – Security & Privacy Engine
Implements:
- Passwordless Authentication (Email OTP with cryptographic salting, single-use, max attempts)
- Strict Session Isolation (Cryptographic tokens, HttpOnly/SameSite cookies, zero cross-session leakage)
- Zero Permanent Storage (Ephemeral in-memory structures with active auto-destruction)
- Anti-Abuse & Rate Limiting (Sliding window IP and identifier throttling)
- Privacy-Preserving Security Monitoring (Aggregate metrics, zero PII exposure)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import smtplib
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("numbershield.security")

# Configurable Durations (Seconds) - override via environment variables
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))          # 5 minutes
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "1800"))  # 30 minutes inactivity
SCAN_TTL_SECONDS = int(os.getenv("SCAN_TTL_SECONDS", "900"))        # 15 minutes
CLEANUP_INTERVAL_SECONDS = 30                                       # Background sweep every 30s

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_token(token: str, salt: str) -> str:
    """Computes a SHA-256 digest of token with salt."""
    return hashlib.sha256(f"{salt}:{token}".encode("utf-8")).hexdigest()


def mask_email(email: str) -> str:
    """Masks an email address for privacy-safe logs/display (e.g. j***n@example.com)."""
    if not email or "@" not in email:
        return "***"
    user, domain = email.split("@", 1)
    if len(user) <= 2:
        masked_user = user[0] + "*"
    else:
        masked_user = user[0] + "*" * (len(user) - 2) + user[-1]
    return f"{masked_user}@{domain}"


# ==============================================================================
# 1. Ephemeral OTP Management
# ==============================================================================

@dataclass
class OTPChallenge:
    email: str
    hashed_otp: str
    salt: str
    created_at: float
    expires_at: float
    attempts_remaining: int = 3
    is_used: bool = False


class OTPManager:
    """Handles ephemeral, single-use, rate-limited email OTPs."""

    def __init__(self, ttl_seconds: int = OTP_TTL_SECONDS):
        self.ttl = ttl_seconds
        self._challenges: Dict[str, OTPChallenge] = {}  # key: normalized email
        self._lock = threading.Lock()
        # For development / testing environments when SMTP is not configured:
        # Stores the latest generated code in memory exclusively for automated tests
        self._dev_last_otp: Dict[str, str] = {}

    def create_otp(self, email: str) -> Tuple[bool, str]:
        """Generates a secure 6-digit OTP and dispatches it."""
        norm_email = email.strip().lower()
        if not EMAIL_REGEX.match(norm_email):
            return False, "Invalid email format"

        with self._lock:
            # Check for existing valid challenge (anti-spam cooldown: 10s in dev, 30s in prod)
            existing = self._challenges.get(norm_email)
            is_dev = os.getenv("ENVIRONMENT", "development").lower() == "development"
            cooldown = 10 if is_dev else 30
            if existing and not existing.is_used and (time.time() - existing.created_at < cooldown):
                remaining = max(1, int(cooldown - (time.time() - existing.created_at)))
                return False, f"Please wait {remaining} seconds before requesting another code."

            # Generate cryptographically secure 6-digit OTP
            otp_code = f"{secrets.randbelow(900000) + 100000:06d}"
            salt = secrets.token_hex(16)
            hashed_otp = hash_token(otp_code, salt)
            now = time.time()

            challenge = OTPChallenge(
                email=norm_email,
                hashed_otp=hashed_otp,
                salt=salt,
                created_at=now,
                expires_at=now + self.ttl,
                attempts_remaining=3,
                is_used=False,
            )
            self._challenges[norm_email] = challenge
            self._dev_last_otp[norm_email] = otp_code

        # Dispatch OTP via transactional email
        sent, err = self._dispatch_email(norm_email, otp_code)
        if not sent:
            logger.error(f"Transactional email delivery failed for {mask_email(norm_email)}: {err}")
            return False, f"Email delivery failed: {err}"

        # NEVER return the raw OTP to the API caller or log it
        return True, "Verification code sent to your email."

    def verify_otp(self, email: str, user_otp: str) -> Tuple[bool, str]:
        """Validates the OTP with constant-time comparison, single-use invalidation, and attempt throttling."""
        norm_email = email.strip().lower()
        clean_otp = re.sub(r"[\s-]+", "", user_otp.strip())

        with self._lock:
            challenge = self._challenges.get(norm_email)
            if not challenge:
                return False, "No active verification code found. Please request a new one."

            if challenge.is_used:
                return False, "Verification code has already been used. Please request a new one."

            if time.time() > challenge.expires_at:
                del self._challenges[norm_email]
                return False, "Verification code has expired. Please request a new one."

            if challenge.attempts_remaining <= 0:
                del self._challenges[norm_email]
                return False, "Too many failed attempts. Code invalidated."

            challenge.attempts_remaining -= 1

            # Compute candidate hash with stored salt
            candidate_hash = hash_token(clean_otp, challenge.salt)
            matches = hmac.compare_digest(candidate_hash, challenge.hashed_otp)

            if not matches:
                if challenge.attempts_remaining == 0:
                    del self._challenges[norm_email]
                    return False, "Invalid code. Maximum attempts exceeded. Code invalidated."
                return False, f"Invalid verification code. {challenge.attempts_remaining} attempt(s) remaining."

            # Valid! Mark as used immediately (single-use enforcement) and clean up
            challenge.is_used = True
            del self._challenges[norm_email]
            self._dev_last_otp.pop(norm_email, None)
            return True, "Email verified successfully."

    def get_dev_otp(self, email: str) -> Optional[str]:
        """Used ONLY by automated self-tests in test mode."""
        return self._dev_last_otp.get(email.strip().lower())

    def cleanup_expired(self) -> int:
        """Removes expired OTP challenges."""
        now = time.time()
        with self._lock:
            expired = [k for k, v in self._challenges.items() if now > v.expires_at or v.is_used]
            for k in expired:
                del self._challenges[k]
                self._dev_last_otp.pop(k, None)
            return len(expired)

    def _dispatch_email(self, to_email: str, otp_code: str) -> Tuple[bool, str]:
        """Sends OTP through configured SMTP provider, or notes dev mode fallback."""
        smtp_host = os.getenv("SMTP_HOST", "").strip()
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER", "").strip()
        smtp_pass = os.getenv("SMTP_PASS", "").strip().replace(" ", "")
        smtp_from = os.getenv("SMTP_FROM", "").strip()

        # Auto-configure host and sender if user provides Gmail credentials
        if smtp_host in ("smtp.example.com", "example.com") or not smtp_host:
            if smtp_user.endswith("@gmail.com"):
                smtp_host = "smtp.gmail.com"
                smtp_port = 587

        if not smtp_from or "yourdomain.com" in smtp_from or "example.com" in smtp_from or smtp_from == "no-reply@numbershield.local":
            smtp_from = smtp_user or "no-reply@numbershield.local"

        if not (smtp_host and smtp_user and smtp_pass) or smtp_host in ("smtp.example.com", "example.com"):
            # SMTP not configured - running in development/local mode
            logger.info(
                f"[DEV MODE] OTP generated for {mask_email(to_email)}. "
                "Configure SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS in .env for live email delivery."
            )
            return True, "Development mode: OTP generated in ephemeral memory."

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = "NumberShield — Your Verification Code"
            msg["From"] = smtp_from
            msg["To"] = to_email

            text_content = (
                f"Hello,\n\n"
                f"Your NumberShield one-time verification code is: {otp_code}\n\n"
                f"This code will expire in 5 minutes and can only be used once.\n"
                f"If you did not request this code, you can safely ignore this email.\n\n"
                f"— NumberShield Privacy Team"
            )
            html_content = f"""
            <div style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:24px;border-radius:8px;max-width:500px">
              <h2 style="color:#58a6ff;margin-top:0">NumberShield</h2>
              <p>Your one-time verification code is:</p>
              <div style="font-size:32px;font-weight:bold;letter-spacing:6px;color:#39d353;margin:20px 0;padding:12px;background:#161b22;text-align:center;border-radius:6px">
                {otp_code}
              </div>
              <p style="font-size:13px;color:#8b949e">Expires in 5 minutes. Single-use only. Do not share this code.</p>
            </div>
            """
            msg.attach(MIMEText(text_content, "plain"))
            msg.attach(MIMEText(html_content, "html"))

            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_from, [to_email], msg.as_string())
            return True, "Sent"
        except Exception as e:
            return False, str(e)


# ==============================================================================
# 2. Strict Ephemeral Session Isolation
# ==============================================================================

@dataclass
class UserSession:
    session_id: str
    email: str
    created_at: float
    last_activity: float
    is_authenticated: bool
    scan_results: Dict[str, Any] = field(default_factory=dict)
    draft_requests: List[Dict[str, Any]] = field(default_factory=list)
    consents: Dict[int, str] = field(default_factory=dict)  # service_id -> status


class SessionManager:
    """
    Maintains cryptographically isolated, server-side in-memory user sessions.
    - Each session has its own private scan results and consent overrides.
    - Person A can NEVER access Person B's session or scans.
    - Zero permanent storage. Automatically purged after inactivity.
    """

    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS):
        self.ttl = ttl_seconds
        self._sessions: Dict[str, UserSession] = {}  # key: session_id
        self._lock = threading.Lock()

    def create_session(self, email: str) -> UserSession:
        """Creates a fresh, isolated session with an unpredictable 256-bit token."""
        session_id = secrets.token_urlsafe(32)
        now = time.time()
        sess = UserSession(
            session_id=session_id,
            email=email.strip().lower(),
            created_at=now,
            last_activity=now,
            is_authenticated=True,
        )
        with self._lock:
            self._sessions[session_id] = sess
        return sess

    def get_session(self, session_id: Optional[str]) -> Optional[UserSession]:
        """Retrieves and touches an active session if valid and not expired."""
        if not session_id:
            return None
        with self._lock:
            sess = self._sessions.get(session_id)
            if not sess:
                return None
            now = time.time()
            if now - sess.last_activity > self.ttl:
                del self._sessions[session_id]
                return None
            sess.last_activity = now
            return sess

    def invalidate_session(self, session_id: Optional[str]) -> bool:
        """Destroys a session on logout."""
        if not session_id:
            return False
        with self._lock:
            if session_id in self._sessions:
                # Clear all user temporary data from memory
                sess = self._sessions.pop(session_id)
                sess.scan_results.clear()
                sess.draft_requests.clear()
                sess.consents.clear()
                return True
            return False

    def cleanup_expired(self) -> int:
        """Removes sessions that exceeded inactivity TTL."""
        now = time.time()
        count = 0
        with self._lock:
            expired = [sid for sid, s in self._sessions.items() if (now - s.last_activity > self.ttl)]
            for sid in expired:
                s = self._sessions.pop(sid)
                s.scan_results.clear()
                s.draft_requests.clear()
                s.consents.clear()
                count += 1
        return count

    def active_session_count(self) -> int:
        with self._lock:
            return len(self._sessions)


# ==============================================================================
# 3. Ephemeral Scan Result Manager
# ==============================================================================

@dataclass
class EphemeralScanResult:
    scan_id: str
    owner_session_id: str
    owner_email: str
    query_type: str
    target_identifier_masked: str
    findings: List[Dict[str, Any]]
    summary: Dict[str, Any]
    created_at: float
    expires_at: float


class ScanResultManager:
    """
    Manages temporary scan results with strict ownership checks.
    - Associated strictly with owner's session.
    - Expired after SCAN_TTL_SECONDS (15 minutes).
    - Can be exported locally by the owner; never permanently retained on server.
    """

    def __init__(self, ttl_seconds: int = SCAN_TTL_SECONDS):
        self.ttl = ttl_seconds
        self._scans: Dict[str, EphemeralScanResult] = {}
        self._lock = threading.Lock()

    def store_scan(
        self,
        session_id: str,
        owner_email: str,
        query_type: str,
        target_masked: str,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any],
    ) -> EphemeralScanResult:
        scan_id = uuid.uuid4().hex
        now = time.time()
        record = EphemeralScanResult(
            scan_id=scan_id,
            owner_session_id=session_id,
            owner_email=owner_email,
            query_type=query_type,
            target_identifier_masked=target_masked,
            findings=findings,
            summary=summary,
            created_at=now,
            expires_at=now + self.ttl,
        )
        with self._lock:
            self._scans[scan_id] = record
        return record

    def get_scan(self, scan_id: str, session_id: str) -> Optional[EphemeralScanResult]:
        """Enforces ownership: returns scan ONLY if owned by requesting session and not expired."""
        with self._lock:
            record = self._scans.get(scan_id)
            if not record:
                return None
            if time.time() > record.expires_at:
                del self._scans[scan_id]
                return None
            # STRICT OWNERSHIP CHECK: Cross-session access is completely forbidden
            if record.owner_session_id != session_id:
                logger.warning(
                    f"IDOR attempt detected: Session {session_id[:8]} tried to access scan {scan_id} belonging to {record.owner_session_id[:8]}"
                )
                return None
            return record

    def cleanup_expired(self) -> int:
        now = time.time()
        count = 0
        with self._lock:
            expired = [sid for sid, s in self._scans.items() if now > s.expires_at]
            for sid in expired:
                del self._scans[sid]
                count += 1
        return count

    def active_scan_count(self) -> int:
        with self._lock:
            return len(self._scans)


# ==============================================================================
# 4. Anti-Abuse & Rate Limiting Engine
# ==============================================================================

class RateLimiter:
    """Sliding-window rate limiter for IP addresses and email endpoints."""

    def __init__(self):
        # key -> list of float timestamps
        self._requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def check_rate_limit(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
        """
        Returns (is_allowed, seconds_until_reset).
        Does NOT record the request; caller must call record_request on success.
        """
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            history = self._requests.get(key, [])
            valid_history = [t for t in history if t > cutoff]
            self._requests[key] = valid_history

            if len(valid_history) >= max_requests:
                oldest = valid_history[0]
                wait = max(1, int(oldest + window_seconds - now))
                return False, wait
            return True, 0

    def record_request(self, key: str):
        now = time.time()
        with self._lock:
            if key not in self._requests:
                self._requests[key] = []
            self._requests[key].append(now)

    def cleanup(self):
        now = time.time()
        cutoff = now - 3600
        with self._lock:
            empty_keys = []
            for k, history in self._requests.items():
                self._requests[k] = [t for t in history if t > cutoff]
                if not self._requests[k]:
                    empty_keys.append(k)
            for k in empty_keys:
                del self._requests[k]


# ==============================================================================
# 5. Privacy-Preserving Security Monitoring & Self-Test Auditor
# ==============================================================================

class SecurityAuditor:
    """Tracks operational security metrics with zero PII and runs automated verification."""

    def __init__(self):
        self.stats = {
            "otp_requests_total": 0,
            "otp_verifications_successful": 0,
            "otp_verifications_failed": 0,
            "sessions_created_total": 0,
            "sessions_destroyed_total": 0,
            "scans_executed_total": 0,
            "rate_limit_blocks_total": 0,
            "idor_blocks_total": 0,
            "purged_records_total": 0,
            "last_cleanup_timestamp": now_utc(),
        }
        self.last_test_results: List[Dict[str, Any]] = []
        self.last_test_time: Optional[str] = None
        self._lock = threading.Lock()

    def increment(self, metric: str, amount: int = 1):
        with self._lock:
            if metric in self.stats:
                self.stats[metric] += amount

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self.stats)

    def record_test_run(self, results: List[Dict[str, Any]]):
        with self._lock:
            self.last_test_results = results
            self.last_test_time = now_utc()


# ==============================================================================
# 6. Global Singleton Instances & Background Cleanup Daemon
# ==============================================================================

otp_manager = OTPManager()
session_manager = SessionManager()
scan_manager = ScanResultManager()
rate_limiter = RateLimiter()
security_auditor = SecurityAuditor()


def _background_cleanup_loop():
    """Continuously purges expired OTPs, sessions, and scans every 30 seconds."""
    while True:
        try:
            time.sleep(CLEANUP_INTERVAL_SECONDS)
            purged_otp = otp_manager.cleanup_expired()
            purged_sessions = session_manager.cleanup_expired()
            purged_scans = scan_manager.cleanup_expired()
            rate_limiter.cleanup()
            total_purged = purged_otp + purged_sessions + purged_scans
            if total_purged > 0:
                security_auditor.increment("purged_records_total", total_purged)
            security_auditor.stats["last_cleanup_timestamp"] = now_utc()
        except Exception as e:
            logger.error(f"Error in security background cleanup: {e}")


_cleanup_thread = threading.Thread(target=_background_cleanup_loop, daemon=True, name="NumberShield-DataDestruction")
_cleanup_thread.start()

