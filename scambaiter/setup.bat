@echo off
REM ===== Scambaiter one-time setup (run once on the demo laptop) =====
cd /d "%~dp0"
echo.
echo [1/3] Creating Python environment (.venv)...
if not exist .venv\Scripts\python.exe python -m venv .venv
call .venv\Scripts\activate.bat
echo [2/3] Installing packages...
python -m pip install --upgrade pip >nul
pip install -r requirements.txt
echo [3/3] Checking all parts...
python tools\check_contract.py extractor
python tools\check_contract.py graph
python tools\check_contract.py report
python tools\check_contract.py dashboard
python tools\check_contract.py simulator
python tools\check_contract.py bot
echo.
echo Setup finished. If every block above says PASS, double-click run_demo.bat
pause
