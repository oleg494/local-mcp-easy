@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Notion Local MCP Easy

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Creating local Python environment...
    where py >nul 2>&1
    if errorlevel 1 (
        python -m venv .venv
    ) else (
        py -3 -m venv .venv
    )
    if errorlevel 1 goto python_error
)

echo [2/3] Checking dependencies...
".venv\Scripts\python.exe" -c "import mcp, uvicorn, starlette" >nul 2>&1
if errorlevel 1 (
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
    if errorlevel 1 goto install_error
)

echo [3/3] Starting server and secure tunnel...
".venv\Scripts\python.exe" launcher.py
set EXIT_CODE=%errorlevel%
echo.
if not "%EXIT_CODE%"=="0" echo Launcher stopped with error %EXIT_CODE%.
pause
exit /b %EXIT_CODE%

:python_error
echo.
echo ERROR: Python 3.11+ was not found. Install Python and enable "Add Python to PATH".
pause
exit /b 1

:install_error
echo.
echo ERROR: Could not install dependencies. Check internet access and try again.
pause
exit /b 1
