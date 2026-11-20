@echo off
echo Stopping PhishGuard AI Background Service...

:: Find and kill the pythonw process running uvicorn
taskkill /F /IM pythonw.exe /T

echo Service stopped successfully.
timeout /t 3
