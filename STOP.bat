@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Stop Local MCP Easy
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" launcher.py --stop
) else (
    python launcher.py --stop
)
pause
