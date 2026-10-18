@echo off
REM ===== Start Scambaiter for the demo =====
REM   run_demo.bat          start with a clean screen (deletes old sessions)
REM   run_demo.bat keep     keep previous sessions
cd /d "%~dp0"
call .venv\Scripts\activate.bat
set OLLAMA_KEEP_ALIVE=30m
if "%OLLAMA_MODEL%"=="" set OLLAMA_MODEL=qwen2.5:7b
echo Warming up %OLLAMA_MODEL% on the GPU (first time can take a minute)...
ollama run %OLLAMA_MODEL% "hi" >nul 2>&1
start "" cmd /c "timeout /t 3 >nul & start http://localhost:8000"
if /i "%1"=="keep" (python -m backend.main --lan) else (python -m backend.main --lan --reset)
pause
