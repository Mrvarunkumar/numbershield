# NumberShield — Privacy Intelligence Platform

NumberShield is a privacy intelligence and personal data exposure management dashboard. It helps users discover, audit, and take action on how their phone number and personal contact identifiers are exposed across digital services.

---

## Key Features

- **Personal Exposure Dashboard**: Visual risk score, breakdown of exposed services by severity (Low / Medium / High).
- **Consent Tracking & Management**: View and modify consent status (Allowed, Denied, Withdrawn) for tracked services.
- **Privacy Request Generator**: Generate standard data erasure (GDPR Art. 17 / CCPA), consent withdrawal, and data subject access request (DSAR) letters.
- **Audit Trail**: Real-time audit logging of all privacy updates and drafted requests.
- **Privacy Discovery**:
  - **Have I Been Pwned Integration**: Public breach catalogue search (free, no API key required) and account breach lookups.
  - **Google Web Search**: Custom Search Engine query to detect public indexing of contact numbers.
  - **Gmail Evidence Scan**: Read-only OAuth check for service registrations and confirmation emails.

---

## Architecture: Zero External Database Needed

NumberShield runs entirely with an **in-memory storage engine**:

- **No Database Setup**: No need to configure PostgreSQL, Supabase, SQLite, or cloud credentials.
- **Privacy by Design**: Data lives strictly in the server process memory and is never persisted to disk.
- **Auto-Cleanup (TTL)**: Data automatically resets to demo defaults after 30 minutes of inactivity.
- **Restart Reset**: Every time the server restarts, state cleanly reinitializes.

---

## Project Structure

```
numbershield/
│
├── backend/                  # FastAPI Backend API
│   ├── __init__.py
│   ├── main.py              # Application routes & middleware
│   └── db.py                # In-memory storage engine with TTL auto-cleanup
│
├── frontend/                 # Web Interface
│   ├── index.html           # Single-page dashboard
│   ├── app.js               # Frontend application logic
│   └── style.css            # Custom styles & dark theme
│
├── .env.example             # Optional API keys template (Gmail, Google CSE, HIBP)
├── .gitignore               # Git ignore rules
├── README.md                # Project documentation
├── requirements.txt         # Python dependencies
├── run.bat                  # One-click startup for Windows Command Prompt
└── run.ps1                  # Startup script for PowerShell
```

---

## Quick Start

### 1. Install Dependencies

Ensure Python 3.9+ is installed:

```bash
pip install -r requirements.txt
```

### 2. Run the Application

**Option A (Windows batch):**
Double-click `run.bat` or run:
```cmd
run.bat
```

**Option B (PowerShell):**
```powershell
.\run.ps1
```

**Option C (Direct Uvicorn command):**
```bash
uvicorn backend.main:app --reload
```

### 3. Open in Browser

Open your browser and navigate to:
```
http://127.0.0.1:8000
```

- **Interactive API Docs (Swagger)**: [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs)
- **Alternative Docs (ReDoc)**: [http://127.0.0.1:8000/api/redoc](http://127.0.0.1:8000/api/redoc)

---

## Optional Integrations

All core features work immediately out-of-the-box without any `.env` file. If you wish to enable third-party discovery providers, copy `.env.example` to `.env` and fill in the optional keys:

- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`: For Gmail OAuth discovery
- `GOOGLE_CSE_API_KEY` / `GOOGLE_CSE_CX`: For Google Custom Search lookup
- `HIBP_API_KEY`: For Have I Been Pwned personal account breach lookup
