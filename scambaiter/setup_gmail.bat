@echo off
REM ===== Connect a Gmail inbox to Scambaiter (one time) =====
cd /d "%~dp0"
call .venv\Scripts\activate.bat
python -m backend.mail setup
python -m backend.mail test
pause
