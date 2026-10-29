# ==============================================================================
# NumberShield - Run Server (PowerShell)
# ==============================================================================
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Ensure we run from the project directory
Set-Location $ScriptDir

# Use the virtual environment Python directly
$PythonExe = Join-Path $ScriptDir "backend\env\Scripts\python.exe"

if (-not (Test-Path $PythonExe)) {
    Write-Host "Virtual environment python not found at $PythonExe. Using system python..." -ForegroundColor Yellow
    $PythonExe = "python"
}

Write-Host "Starting NumberShield backend server on http://127.0.0.1:8000 ..." -ForegroundColor Cyan
& $PythonExe -m uvicorn backend.main:app --reload
