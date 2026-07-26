@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Local MCP Easy doctor
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" launcher.py --doctor
) else (
    python launcher.py --doctor
)
pause
