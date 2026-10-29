# NumberShield MVP

A privacy intelligence platform for tracking synthetic phone-number disclosures, managing consent records, and drafting privacy requests, powered by **FastAPI** and **Supabase (PostgreSQL)**.

## Important
- Consent changes update NumberShield only; they do not notify external services automatically.
- Exposure entries are synthetic demo records, not an internet-wide scan.
- Privacy requests are drafts only and are not sent.
- Never enter real sensitive credentials or OTPs in this demo.

## Database: Supabase Setup
1. Create a project at [supabase.com](https://supabase.com/).
2. In Supabase Dashboard, open **SQL Editor** -> **New Query**.
3. Copy & paste the contents of [`supabase_schema.sql`](file:///c:/Users/Varun%20Kumar/OneDrive/Desktop/NumberShield_hackthon/main/supabase_schema.sql) and click **Run**.
4. Copy your `Project URL` and `anon / service_role API key` into [`.env`](file:///c:/Users/Varun%20Kumar/OneDrive/Desktop/NumberShield_hackthon/main/.env).

## Configuration (`.env`)
Edit [`.env`](file:///c:/Users/Varun%20Kumar/OneDrive/Desktop/NumberShield_hackthon/main/.env) in the project folder with your credentials:
```env
# Supabase
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_KEY=your-supabase-anon-or-service-role-key

# Google OAuth / Gmail API (Discovery)
GOOGLE_CLIENT_ID=your-google-oauth-client-id
GOOGLE_CLIENT_SECRET=your-google-oauth-client-secret
GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/api/discovery/gmail/callback

# Google Programmable Search (Public Web)
GOOGLE_CSE_API_KEY=your-google-search-api-key
GOOGLE_CSE_CX=your-search-engine-id

# Have I Been Pwned API (Breach Catalogue)
HIBP_API_KEY=your-hibp-api-key
```

Alternatively, on Windows PowerShell, you can run [`setup_env.ps1`](file:///c:/Users/Varun%20Kumar/OneDrive/Desktop/NumberShield_hackthon/main/setup_env.ps1):
```powershell
.\setup_env.ps1
```

## Running the Application

### Windows PowerShell
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn backend.main:app --reload
```
Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and API docs at [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs).

### Verification
Run the verification test suite to ensure all endpoints and frontend DOM bindings are healthy:
```powershell
python verify_full_system.py
```
