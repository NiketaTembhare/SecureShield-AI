# SecureShield Unified Startup Script
# This script launches both the Flask Backend and Vite Frontend together.

Write-Host "--- Starting SecureShield AI Gateway ---" -ForegroundColor Cyan

# 1. Start Backend with VIRTUAL ENV for stability
Write-Host "[1/2] Launching Backend (Port 8000)..." -ForegroundColor Yellow
$PythonPath = ".\backend\.venv\Scripts\python.exe"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd secureSheild/backend; & '.\.venv\Scripts\python.exe' app.py" -WindowStyle Normal

# Wait a few seconds for backend to initialize
Start-Sleep -Seconds 5

# 2. Start Frontend
Write-Host "[2/2] Launching Frontend (Port 5173)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd secureSheild/frontend; npm run dev" -WindowStyle Normal

Write-Host "`nSuccessfully launched both services!" -ForegroundColor Green
Write-Host "Backend: http://localhost:8000"
Write-Host "Frontend: http://localhost:5173"
Write-Host "`nKeep the opened PowerShell windows running to use the app." -ForegroundColor Cyan
