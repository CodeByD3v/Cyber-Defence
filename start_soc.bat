@echo off
title SOC Platform - Real-Time Attack Detection

echo.
echo  SOC REAL-TIME ATTACK DETECTION PLATFORM
echo  ========================================
echo.

REM Check for Python
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo  Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

echo  Starting server...
echo.
echo  Backend:  http://127.0.0.1:8765
echo  Commands: /help, /attack, /zeek-pcap
echo  Press Ctrl+C to stop
echo.

REM Open browser after delay
start /b cmd /c "timeout /t 2 /nobreak >nul && start http://127.0.0.1:8765"

REM Run the server
python -m backend.server

echo.
echo  Server stopped.
pause
