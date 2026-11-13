@echo off
cd /d "%~dp0"
echo Starting NumberShield on http://127.0.0.1:8000 ...

if exist "%~dp0backend\env\Scripts\python.exe" (
    "%~dp0backend\env\Scripts\python.exe" -m uvicorn backend.main:app --reload
) else if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -m uvicorn backend.main:app --reload
) else (
    echo Using system python...
    python -m uvicorn backend.main:app --reload
)
pause
