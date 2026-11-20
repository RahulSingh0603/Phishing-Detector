@echo off
echo Starting PhishGuard AI Background Service...
cd /d "%~dp0\.."

:: Check if venv exists, if not, exit
if not exist venv\Scripts\python.exe (
    echo Virtual environment not found! Please run installation first.
    pause
    exit /b 1
)

:: Start the Python backend using pythonw (no console window)
start "" /B venv\Scripts\pythonw.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000

echo Service started successfully!
echo The API is running at http://127.0.0.1:8000
echo You can now close this window.
timeout /t 3
