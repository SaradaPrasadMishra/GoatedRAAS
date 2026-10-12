@echo off
REM ===== Stage moment: 3 linked scam calls arrive while the dashboard is on screen =====
REM Start run_demo.bat first, then double-click this.
cd /d "%~dp0"
call .venv\Scripts\activate.bat
python -m simulator.run --live
pause
