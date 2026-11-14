@echo off
title NumberShield — HTTP Dev Mode (not secure)
color 0E
echo.
echo  =====================================================
echo   NumberShield Enterprise — HTTP Dev Mode
echo   http://localhost:8000  (NOT secure — dev only)
echo  =====================================================
echo.

cd /d "%~dp0"

echo [WARN]  Running in HTTP mode. Use start_https.bat for secure mode.
echo.
echo  Open your browser at:  http://localhost:8000
echo  Press Ctrl+C to stop.
echo.

.venv\Scripts\python.exe -m uvicorn backend.main:app ^
    --host 127.0.0.1 ^
    --port 8000 ^
    --reload

pause

