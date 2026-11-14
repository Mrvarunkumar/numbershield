@echo off
title NumberShield — HTTPS Secure Mode
color 0A
echo.
echo  =====================================================
echo   NumberShield Enterprise — HTTPS Secure Mode
echo   https://localhost:8443
echo  =====================================================
echo.

cd /d "%~dp0"

REM Check certs exist
if not exist "certs\cert.pem" (
    echo [ERROR] TLS certificate not found: certs\cert.pem
    echo         Run setup first. See README_HTTPS.md
    pause
    exit /b 1
)
if not exist "certs\key.pem" (
    echo [ERROR] TLS key not found: certs\key.pem
    echo         Run setup first. See README_HTTPS.md
    pause
    exit /b 1
)

echo [INFO]  Certificate : certs\cert.pem
echo [INFO]  Private Key : certs\key.pem
echo [INFO]  Starting server on https://127.0.0.1:8443
echo.
echo  Open your browser at:  https://localhost:8443
echo  (Accept the security warning the FIRST time — it is a local dev cert)
echo.
echo  Press Ctrl+C to stop the server.
echo.

.venv\Scripts\python.exe -m uvicorn backend.main:app ^
    --host 127.0.0.1 ^
    --port 8443 ^
    --ssl-certfile certs/cert.pem ^
    --ssl-keyfile  certs/key.pem ^
    --reload

pause

