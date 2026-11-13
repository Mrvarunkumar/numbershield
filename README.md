# NumberShield 2.0 — Privacy-First Public Digital Exposure Checker

> **"Your Digital Exposure. Your Privacy. Your Control."**
> **Core Principle:** VERIFY OWNERSHIP BEFORE ACCESS. NEVER TRUST AN EMAIL ADDRESS ALONE. NEVER EXPOSE PRIVATE USER INFORMATION.

NumberShield 2.0 is a privacy-first, evidence-based exposure defense platform. It protects user identity with passwordless authentication, strict session isolation, and automatic data destruction — operating with **zero permanent personal databases**.

---

## 1. Core Security Architecture

1. **No Unauthorized Private Gmail or Google Access**:
   - Mailbox reading (`gmail.readonly`) is permanently removed and prohibited by architecture.
   - Google Sign-In is restricted strictly to OpenID Connect (`openid email profile`) for authentication only.
2. **Passwordless Authentication**:
   - Single-use 6-digit Email OTP with cryptographic salting (SHA-256).
   - 5-minute expiration, max 3 verification attempts, brute-force lockout.
   - Zero application passwords stored anywhere.
3. **Strict Session Isolation (Person A vs Person B Protection)**:
   - Cryptographically random 256-bit session tokens in `HttpOnly`, `SameSite=Lax` cookies.
   - Person B entering Person A's email can never access Person A's session or scans without proving ownership.
   - IDOR defense: scan results are accessible only by the owning session.
4. **Zero Permanent Personal Data**:
   - No PostgreSQL, no Supabase, no SQLite, no persistent database.
   - All state is held in ephemeral server-side memory.
5. **Automatic Data Destruction**:
   - OTP codes: auto-purged after 5 minutes.
   - Inactive sessions: auto-purged after 30 minutes.
   - Ephemeral scan results: auto-purged after 15 minutes.
   - Continuous background sweep daemon runs every 30 seconds.
6. **Public Digital Exposure Search Only**:
   - Queries verified public sources: Have I Been Pwned Public Incident Catalogue & Google Programmable Search.
   - Findings classified as: `VERIFIED PUBLIC INFORMATION`, `UNVERIFIED INFORMATION`, `NO PUBLIC RESULTS FOUND`, `SOURCE UNAVAILABLE`, `SEARCH FAILED`.
   - Local report export streamed directly; never permanently saved on the server.
7. **Privacy Audit Dashboard**:
   - Real-time administrative security monitor with zero PII exposure.
   - Live automated self-tests verifying session isolation, single-use OTPs, and brute-force defenses.

---

## 2. Project Layout

```
numbershield/
├── backend/
│   ├── __init__.py
│   ├── main.py                   # FastAPI routes, security headers, middleware
│   ├── security.py               # OTP manager, session isolator, rate limiter, audit engine
│   ├── db.py                     # Ephemeral in-memory store with session scoping
│   └── test_security_suite.py    # 25-criteria automated security test suite
├── frontend/
│   ├── index.html                # Single-page application UI with auth modal & audit view
│   ├── app.js                    # Controller logic, OTP flows, local report export
│   └── style.css                 # Cyber-defense dark theme & security widgets
├── .env.example                  # Environment configuration template
├── .gitignore                    # Git rules (excludes .env and secrets)
├── README.md                     # Documentation
├── requirements.txt              # Core dependencies
├── run.bat                       # One-click startup for Windows Command Prompt
└── run.ps1                       # Startup script for PowerShell
```

---

## 3. Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
- **Windows Command Prompt:**
  ```cmd
  run.bat
  ```
- **PowerShell:**
  ```powershell
  .\run.ps1
  ```
- **Direct Uvicorn:**
  ```bash
  uvicorn backend.main:app --reload
  ```

### 3. Open in Browser
- **Application:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive OpenAPI Documentation:** [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs)
- **Privacy Audit Dashboard:** Navigate to the **Security Audit** tab in the sidebar.

---

## 4. Automated Security Verification

To run the complete 25-criteria automated security verification test suite:

```bash
python -m unittest backend.test_security_suite -v
```
All tests execute deterministically in memory in < 0.2 seconds.
