@echo off
cd /d "%~dp0"
echo Starting NumberShield on http://127.0.0.1:8000 ...
"%~dp0backend\env\Scripts\python.exe" -m uvicorn backend.main:app --reload
pause
