# ==============================================================================
# NumberShield - PowerShell Environment Variable Setup
# ==============================================================================
# Run this script in PowerShell prior to starting uvicorn:
#   .\setup_env.ps1
# ==============================================================================

# Supabase Credentials
$env:SUPABASE_URL = "https://your-project-id.supabase.co"
$env:SUPABASE_KEY = "your-supabase-anon-or-service-role-key"
# $env:DATABASE_URL = "postgresql://postgres.your-project-ref:your-db-password@aws-0-region.pooler.supabase.com:6543/postgres?sslmode=require"

# Google OAuth / Gmail API Keys
$env:GOOGLE_CLIENT_ID = "your-google-oauth-client-id"
$env:GOOGLE_CLIENT_SECRET = "your-google-oauth-client-secret"
$env:GOOGLE_REDIRECT_URI = "http://127.0.0.1:8000/api/discovery/gmail/callback"

# Google Programmable Search Engine Keys
$env:GOOGLE_CSE_API_KEY = "your-google-search-api-key"
$env:GOOGLE_CSE_CX = "your-search-engine-id"

# Have I Been Pwned API Key
$env:HIBP_API_KEY = "your-hibp-api-key"

Write-Host "NumberShield environment variables loaded successfully." -ForegroundColor Green
