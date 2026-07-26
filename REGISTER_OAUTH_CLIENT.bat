@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Register OAuth client for Local MCP Easy
if not exist ".venv\Scripts\python.exe" (
    where py >nul 2>&1
    if errorlevel 1 (python -m venv .venv) else (py -3 -m venv .venv)
)
rem --register-oauth-client imports auth\, which imports the mcp package, so
rem the dependencies must be present. Without this it crashed with a bare
rem ModuleNotFoundError whenever SETUP.bat had run but START.bat had not.
rem register_oauth_client.sh has always installed them; the .bat had drifted.
".venv\Scripts\python.exe" -c "import mcp, uvicorn, starlette" >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
    if errorlevel 1 goto install_error
)
".venv\Scripts\python.exe" launcher.py --register-oauth-client
pause
exit /b %errorlevel%

:install_error
echo.
echo ERROR: Could not install dependencies. Check internet access and try again.
pause
exit /b 1
