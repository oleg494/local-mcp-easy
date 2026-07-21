@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Building release archive into .\release\
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" build_release.py
) else (
    python build_release.py
)
pause
