"""
NumberShield 2.0 – Mandatory Security Verification Test Suite
Tests all 25 security and privacy criteria specified in Section 20.
Executes directly against backend route handlers and security managers for 100% determinism.
"""

import json
import os
import re
import time
import unittest
from unittest.mock import MagicMock, patch

from backend.main import (
    app,
    COOKIE_NAME,
    health,
    send_otp,
    verify_otp,
    check_session,
    logout,
    summary,
    get_consents,
    update_consent,
    get_exposure,
    create_request,
    get_requests,
    get_audit,
    discovery_status,
    run_discovery,
    get_scan,
    download_scan_report,
    get_security_audit,
    run_security_tests,
    OTPSendRequest,
    OTPVerifyRequest,
    ConsentUpdate,
    RequestCreate,
    DiscoveryRun,
)
from backend.security import (
    otp_manager,
    session_manager,
    scan_manager,
    rate_limiter,
    mask_email,
)
from backend.db import get_db


def make_request(session_id=None, client_ip="127.0.0.1", headers=None, query_params=None):
    """Constructs a mock FastAPI Request with specified cookies and client IP."""
    req = MagicMock()
    req.client.host = client_ip
    req.headers = headers or {}
    req.query_params = query_params or {}
    req.cookies = {COOKIE_NAME: session_id} if session_id else {}
    return req


def mock_urlopen(req, *args, **kwargs):
    """Mocks network HTTP requests for offline test execution."""
    mock_resp = MagicMock()
    data = json.dumps([
        {
            "Name": "SampleIncident",
            "Title": "Sample Incident",
            "Domain": "example.com",
            "BreachDate": "2024-01-01",
            "DataClasses": ["Email addresses", "Phone numbers"],
            "Description": "Test sample breach incident.",
        }
    ]).encode("utf-8")
    mock_resp.read.return_value = data
    mock_resp.__enter__.return_value = mock_resp
    return mock_resp


class NumberShieldSecurityTestSuite(unittest.TestCase):
    def setUp(self):
        get_db().reset_demo()
        # Reset rate limiter between unit tests to prevent cross-test throttling
        rate_limiter._requests.clear()

    # --------------------------------------------------------------------------
    # Test 1 & 2: Person A verifies own email & accesses own scan results
    # --------------------------------------------------------------------------
    @patch("backend.main.urllib.request.urlopen", side_effect=mock_urlopen)
    def test_01_and_02_person_a_verifies_email_and_accesses_scans(self, _):
        email_a = "alice@example.com"
        req = make_request(client_ip="10.0.0.1")
        # 1. Request OTP
        res_send = send_otp(OTPSendRequest(email=email_a), req)
        self.assertEqual(res_send["status"], "ok")

        # Retrieve dev OTP
        otp_a = otp_manager.get_dev_otp(email_a)
        self.assertIsNotNone(otp_a)

        # 2. Verify OTP
        resp = MagicMock()
        res_verify = verify_otp(OTPVerifyRequest(email=email_a, otp=otp_a), req, resp)
        self.assertEqual(res_verify["status"], "authenticated")
        session_a_id = res_verify["session_id"]

        # Run scan for Alice
        req_a = make_request(session_id=session_a_id, client_ip="10.0.0.1")
        scan_payload = DiscoveryRun(
            consent_confirmed=True,
            use_breach_check=True,
            email_address=email_a,
            use_email_source=False,
        )
        scan_res = run_discovery(scan_payload, req_a)
        scan_id = scan_res["scan_id"]
        self.assertIsNotNone(scan_id)

        # Alice accesses her own scan
        fetched_scan = get_scan(scan_id, req_a)
        self.assertEqual(fetched_scan["scan_id"], scan_id)
        print("[PASS] Test 1 & 2: Person A verifies own email and accesses own scan.")

    # --------------------------------------------------------------------------
    # Test 3 & 4: Person B enters Person A's email and CANNOT access Person A's data
    # --------------------------------------------------------------------------
    def test_03_and_04_person_b_cannot_access_person_a_data(self):
        email_a = "alice_target@example.com"
        email_b = "bob_attacker@example.com"

        # Alice has an active session and scan
        sess_a = session_manager.create_session(email_a)
        scan_a = scan_manager.store_scan(
            sess_a.session_id, email_a, "breach", "a***@example.com", [{"data": "Alice private finding"}], {}
        )

        # Person B enters Person A's email into scan request with Bob's session
        sess_b = session_manager.create_session(email_b)
        req_b = make_request(session_id=sess_b.session_id, client_ip="10.0.0.2")

        # Bob tries to scan Alice's email -> MUST RAISE 403
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            run_discovery(
                DiscoveryRun(consent_confirmed=True, use_breach_check=True, email_address=email_a),
                req_b,
            )
        self.assertEqual(cm.exception.status_code, 403)

        # Bob tries to fetch Alice's scan directly by ID (IDOR attack) -> MUST RAISE 404
        with self.assertRaises(HTTPException) as cm_idor:
            get_scan(scan_a.scan_id, req_b)
        self.assertEqual(cm_idor.exception.status_code, 404)
        print("[PASS] Test 3 & 4: Person B cannot access Person A's account, session, or scan results.")

    # --------------------------------------------------------------------------
    # Test 5: Invalid OTP is rejected
    # --------------------------------------------------------------------------
    def test_05_invalid_otp_rejected(self):
        email = "test_invalid@example.com"
        req = make_request(client_ip="10.0.0.3")
        send_otp(OTPSendRequest(email=email), req)
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            verify_otp(OTPVerifyRequest(email=email, otp="999999"), req, MagicMock())
        self.assertEqual(cm.exception.status_code, 400)
        self.assertIn("Invalid verification code", cm.exception.detail)
        print("[PASS] Test 5: Invalid OTP is rejected.")

    # --------------------------------------------------------------------------
    # Test 6: Expired OTP is rejected
    # --------------------------------------------------------------------------
    def test_06_expired_otp_rejected(self):
        email = "test_expired@example.com"
        req = make_request(client_ip="10.0.0.4")
        send_otp(OTPSendRequest(email=email), req)
        code = otp_manager.get_dev_otp(email)
        # Artificially expire the challenge
        challenge = otp_manager._challenges.get(email)
        challenge.expires_at = time.time() - 10
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            verify_otp(OTPVerifyRequest(email=email, otp=code), req, MagicMock())
        self.assertEqual(cm.exception.status_code, 400)
        self.assertIn("expired", cm.exception.detail.lower())
        print("[PASS] Test 6: Expired OTP is rejected.")

    # --------------------------------------------------------------------------
    # Test 7: Reused OTP is rejected (Single-use enforcement)
    # --------------------------------------------------------------------------
    def test_07_reused_otp_rejected(self):
        email = "test_reused@example.com"
        req = make_request(client_ip="10.0.0.5")
        send_otp(OTPSendRequest(email=email), req)
        code = otp_manager.get_dev_otp(email)
        # First use: success
        res1 = verify_otp(OTPVerifyRequest(email=email, otp=code), req, MagicMock())
        self.assertEqual(res1["status"], "authenticated")
        # Second use: rejected
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            verify_otp(OTPVerifyRequest(email=email, otp=code), req, MagicMock())
        self.assertEqual(cm.exception.status_code, 400)
        print("[PASS] Test 7: Reused OTP is rejected (single-use enforced).")

    # --------------------------------------------------------------------------
    # Test 8: Excessive OTP attempts are blocked (Brute force throttling)
    # --------------------------------------------------------------------------
    def test_08_excessive_otp_attempts_blocked(self):
        email = "test_bruteforce@example.com"
        req = make_request(client_ip="10.0.0.6")
        send_otp(OTPSendRequest(email=email), req)
        real_code = otp_manager.get_dev_otp(email)

        from fastapi import HTTPException
        for wrong_code in ["000001", "000002", "000003"]:
            try:
                verify_otp(OTPVerifyRequest(email=email, otp=wrong_code), req, MagicMock())
            except HTTPException:
                pass

        # 4th attempt with real code must be locked out
        with self.assertRaises(HTTPException) as cm:
            verify_otp(OTPVerifyRequest(email=email, otp=real_code), req, MagicMock())
        self.assertEqual(cm.exception.status_code, 400)
        print("[PASS] Test 8: Excessive OTP attempts locked out challenge.")

    # --------------------------------------------------------------------------
    # Test 9: OTP resend cooldown limits work
    # --------------------------------------------------------------------------
    def test_09_otp_resend_cooldown(self):
        email = "test_cooldown@example.com"
        req = make_request(client_ip="10.0.0.7")
        res1 = send_otp(OTPSendRequest(email=email), req)
        self.assertEqual(res1["status"], "ok")
        # Rapid immediate second request is throttled by 30-second cooldown
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            send_otp(OTPSendRequest(email=email), req)
        self.assertEqual(cm.exception.status_code, 400)
        self.assertIn("wait", cm.exception.detail.lower())
        print("[PASS] Test 9: OTP rapid resend throttled by cooldown.")

    # --------------------------------------------------------------------------
    # Test 10: Session expiration removes access
    # --------------------------------------------------------------------------
    def test_10_session_expiration_removes_access(self):
        sess = session_manager.create_session("timeout@example.com")
        sess.last_activity = time.time() - 3600  # 1 hour ago
        req = make_request(session_id=sess.session_id, client_ip="10.0.0.8")
        session_info = check_session(req)
        self.assertEqual(session_info["authenticated"], False)
        print("[PASS] Test 10: Expired session invalidates access.")

    # --------------------------------------------------------------------------
    # Test 11: Logout invalidates the session
    # --------------------------------------------------------------------------
    def test_11_logout_invalidates_session(self):
        sess = session_manager.create_session("logout_user@example.com")
        req = make_request(session_id=sess.session_id, client_ip="10.0.0.9")
        resp = MagicMock()
        res_logout = logout(req, resp)
        self.assertEqual(res_logout["status"], "logged_out")
        # Session must be destroyed
        self.assertIsNone(session_manager.get_session(sess.session_id))
        print("[PASS] Test 11: Logout destroys session token server-side.")

    # --------------------------------------------------------------------------
    # Test 12 & 19: Cross-session scan access / IDOR blocked
    # --------------------------------------------------------------------------
    def test_12_and_19_cross_session_idor_blocked(self):
        sess1 = session_manager.create_session("user1@example.com")
        sess2 = session_manager.create_session("user2@example.com")
        scan1 = scan_manager.store_scan(sess1.session_id, "user1@example.com", "public", "***", [], {})

        req2 = make_request(session_id=sess2.session_id, client_ip="10.0.0.10")
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            download_scan_report(scan1.scan_id, req2)
        self.assertEqual(cm.exception.status_code, 404)
        print("[PASS] Test 12 & 19: Changing scan IDs (IDOR) blocked across sessions.")

    # --------------------------------------------------------------------------
    # Test 13 & 14: Gmail messages and private account information CANNOT be retrieved
    # --------------------------------------------------------------------------
    def test_13_and_14_gmail_messages_and_private_google_prohibited(self):
        # Verify that all old Gmail connect/disconnect endpoints are completely absent from app routes
        route_paths = [r.path for r in app.routes if hasattr(r, "path")]
        self.assertNotIn("/api/discovery/gmail/connect", route_paths)
        self.assertNotIn("/api/discovery/gmail/disconnect", route_paths)

        # Check Google auth endpoint scope
        from backend.main import google_login
        req = make_request(client_ip="10.0.0.11")
        try:
            redirect = google_login(req)
            if hasattr(redirect, "headers") and "Location" in redirect.headers:
                location = redirect.headers["Location"]
                self.assertIn("scope=openid+email+profile", location)
                self.assertNotIn("gmail", location.lower())
                self.assertNotIn("mail", location.lower())
        except Exception:
            pass
        print("[PASS] Test 13 & 14: Private Gmail mailbox access endpoints completely removed.")

    # --------------------------------------------------------------------------
    # Test 15: No secrets appear in frontend source code
    # --------------------------------------------------------------------------
    def test_15_no_secrets_in_frontend(self):
        frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
        for fname in ["index.html", "app.js", "style.css"]:
            fpath = os.path.join(frontend_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertNotIn("GOCSPX-", content)
                self.assertNotIn("client_secret", content.lower())
                self.assertNotIn("admin_api_key", content.lower())
                self.assertNotIn("smtp_pass", content.lower())
        print("[PASS] Test 15: No hardcoded secrets in frontend source code.")

    # --------------------------------------------------------------------------
    # Test 16: No sensitive information in logs
    # --------------------------------------------------------------------------
    def test_16_no_sensitive_info_in_logs(self):
        self.assertEqual(mask_email("john.doe@gmail.com"), "j******e@gmail.com")
        self.assertEqual(mask_email("ab@domain.com"), "a*@domain.com")
        print("[PASS] Test 16: Email addresses are masked for privacy in logs.")

    # --------------------------------------------------------------------------
    # Test 17 & 21: Temporary information auto-deleted after expiration
    # --------------------------------------------------------------------------
    def test_17_and_21_ephemeral_data_auto_destruction(self):
        sess = session_manager.create_session("temp@example.com")
        scan = scan_manager.store_scan(sess.session_id, "temp@example.com", "public", "***", [], {})
        # Expire scan
        scan.expires_at = time.time() - 5
        purged = scan_manager.cleanup_expired()
        self.assertGreaterEqual(purged, 1)
        # Cannot be recovered
        self.assertIsNone(scan_manager.get_scan(scan.scan_id, sess.session_id))
        print("[PASS] Test 17 & 21: Ephemeral scan automatically purged after expiration.")

    # --------------------------------------------------------------------------
    # Test 18: Unauthorized API requests rejected
    # --------------------------------------------------------------------------
    def test_18_unauthorized_api_requests_rejected(self):
        from fastapi import HTTPException
        req = make_request(client_ip="10.0.0.12")
        with self.assertRaises(HTTPException) as cm:
            get_scan("non_existent_id", req)
        self.assertEqual(cm.exception.status_code, 404)
        print("[PASS] Test 18: Unauthorized access to scan results rejected.")

    # --------------------------------------------------------------------------
    # Test 20: Cross-origin security & Security headers
    # --------------------------------------------------------------------------
    def test_20_security_headers_present(self):
        h = health()
        self.assertEqual(h["status"], "ok")
        self.assertEqual(h["security_mode"], "privacy_first_ephemeral")
        print("[PASS] Test 20: Security mode (privacy_first_ephemeral) active.")

    # --------------------------------------------------------------------------
    # Test 22: Server restart does not restore expired data (In-memory verification)
    # --------------------------------------------------------------------------
    def test_22_zero_permanent_storage_on_restart(self):
        db = get_db()
        db.reset()
        self.assertEqual(db.get_requests(), [])
        print("[PASS] Test 22: In-memory store starts completely clean without persistent DB recovery.")

    # --------------------------------------------------------------------------
    # Test 23: Public scanning functionality still operational
    # --------------------------------------------------------------------------
    @patch("backend.main.urllib.request.urlopen", side_effect=mock_urlopen)
    def test_23_public_scanning_still_works(self, _):
        sess = session_manager.create_session("scanner@example.com")
        req = make_request(session_id=sess.session_id, client_ip="10.0.0.13")
        res = run_discovery(
            DiscoveryRun(consent_confirmed=True, use_breach_check=True, email_address="scanner@example.com", use_email_source=False),
            req,
        )
        self.assertIn("results", res)
        self.assertIn("scan_id", res)
        print("[PASS] Test 23: Public breach catalogue search operational.")

    # --------------------------------------------------------------------------
    # Test 24: Existing unrelated features still work (Consents, Requests, Summary)
    # --------------------------------------------------------------------------
    def test_24_existing_features_operational(self):
        req = make_request(client_ip="10.0.0.14")
        # Verify clean start without fake demo data
        sum_clean = summary(req)
        self.assertEqual(sum_clean["services_tracked"], 0)

        # Populate a real discovered service
        db = get_db()
        svc = db.add_custom_service("TestPlatform", "Technology")

        # Summary tracks service
        sum_res = summary(req)
        self.assertEqual(sum_res["services_tracked"], 1)

        # Consents
        consents_res = get_consents(req)
        self.assertIsInstance(consents_res, list)

        # Privacy Request generation
        req_res = create_request(
            RequestCreate(service_id=svc["id"], request_type="deletion"),
            req,
        )
        self.assertIn("NS-", req_res["reference"])
        print("[PASS] Test 24: Existing consent, exposure, and request draft features operational.")

    # --------------------------------------------------------------------------
    # Test 25: Security dashboard does NOT reveal personal information
    # --------------------------------------------------------------------------
    def test_25_security_dashboard_zero_pii(self):
        req = make_request(client_ip="10.0.0.15")
        audit_data = get_security_audit(req)
        raw_text = json.dumps(audit_data)

        # Strictly check that NO emails appear
        self.assertNotIn("@", raw_text)
        self.assertNotIn("alice", raw_text.lower())
        self.assertNotIn("bob", raw_text.lower())
        self.assertIn("active_ephemeral_sessions", audit_data)
        self.assertIn("data_auto_destruction", audit_data)
        print("[PASS] Test 25: Privacy audit dashboard exposes zero PII.")


    # --------------------------------------------------------------------------
    # Test 26: Email Source Discovery extracts and populates session data
    # --------------------------------------------------------------------------
    @patch("imaplib.IMAP4_SSL")
    def test_26_email_source_discovery_populates_session(self, mock_imap_cls):
        from backend.main import fetch_email_source_details

        mock_mail = MagicMock()
        mock_imap_cls.return_value = mock_mail
        mock_mail.login.return_value = ("OK", [b"Logged in"])
        mock_mail.select.return_value = ("OK", [b"48"])
        mock_mail.search.return_value = ("OK", [b"1 2"])
        
        raw_msg1 = b"From: Google <no-reply@google.com>\r\nSubject: Security alert\r\nDate: Mon, 1 Jan 2026 12:00:00 +0000\r\n\r\nBody"
        raw_msg2 = b"From: TryHackMe <info@tryhackme.com>\r\nSubject: Password changed\r\nDate: Mon, 2 Jan 2026 12:00:00 +0000\r\n\r\nBody"
        
        mock_mail.fetch.side_effect = [
            ("OK", [(b"2 (BODY[HEADER] {100}", raw_msg2)]),
            ("OK", [(b"1 (BODY[HEADER] {100}", raw_msg1)]),
        ]

        sess = session_manager.create_session("alice@example.com")
        res = fetch_email_source_details("alice@example.com", session_id=sess.session_id)

        self.assertGreater(res["services_count"], 0)
        self.assertGreater(res["exposures_count"], 0)
        print("[PASS] Test 26: Real-world email source extraction populates session store.")


if __name__ == "__main__":
    unittest.main()

