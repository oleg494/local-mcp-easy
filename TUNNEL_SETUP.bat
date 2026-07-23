@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Configure tunnel backend for Local MCP Easy
if not exist ".venv\Scripts\python.exe" (
    where py >nul 2>&1
    if errorlevel 1 (python -m venv .venv) else (py -3 -m venv .venv)
)
".venv\Scripts\python.exe" launcher.py --tunnel-setup
pause
