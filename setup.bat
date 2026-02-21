@echo off
REM ============================================================
REM BlockSafe Setup Script (Windows)
REM Requires: Python 3.11 installed and in PATH
REM ============================================================

set PYTHON_VERSION=3.11
set VENV_DIR=server\venv
set REQ_FILE=server\requirements.txt

echo ============================================
echo   BlockSafe - Fresh Environment Setup
echo ============================================
echo.

REM ── 1. Locate Python 3.11 ──────────────────────────────────
set PYTHON=
for %%P in (py python) do (
    where %%P >nul 2>&1 && (
        for /f "tokens=2 delims= " %%V in ('%%P --version 2^>^&1') do (
            echo %%V | findstr /B "%PYTHON_VERSION%" >nul && (
                set PYTHON=%%P
                goto :found_python
            )
        )
    )
)

REM Try py launcher with version flag
py -%PYTHON_VERSION% --version >nul 2>&1 && (
    set PYTHON=py -%PYTHON_VERSION%
    goto :found_python
)

echo ERROR: Python %PYTHON_VERSION% not found.
echo Install from: https://www.python.org/downloads/
echo Make sure to check "Add Python to PATH" during installation.
exit /b 1

:found_python
echo [OK] Found Python: %PYTHON%

REM ── 2. Remove old venv if exists ────────────────────────────
if exist "%VENV_DIR%" (
    echo [..] Removing old virtual environment...
    rmdir /s /q "%VENV_DIR%"
    echo [OK] Old venv removed
)

REM ── 3. Create fresh venv ────────────────────────────────────
echo [..] Creating virtual environment...
%PYTHON% -m venv "%VENV_DIR%"
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    exit /b 1
)
echo [OK] Virtual environment created at %VENV_DIR%

REM ── 4. Upgrade pip ─────────────────────────────────────────
echo [..] Upgrading pip...
"%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip --quiet
echo [OK] pip upgraded

REM ── 5. Install dependencies ────────────────────────────────
echo [..] Installing dependencies from %REQ_FILE%...
"%VENV_DIR%\Scripts\pip.exe" install -r "%REQ_FILE%"
if errorlevel 1 (
    echo ERROR: Dependency installation failed
    exit /b 1
)
echo [OK] All dependencies installed

REM ── 6. Verify critical imports ──────────────────────────────
echo [..] Verifying critical imports...
"%VENV_DIR%\Scripts\python.exe" -c "import fastapi, uvicorn, pydantic, langchain, supabase, langchain_groq, langchain_openai; print('[OK] Core imports verified')"
if errorlevel 1 (
    echo ERROR: Import verification failed. Ensure internet connection or check constraints.
    exit /b 1
)

REM ── 7. Check .env file ──────────────────────────────────────
if exist "server\.env" (
    echo [OK] server\.env found
) else (
    echo [!!] server\.env NOT found
    copy "server\.env.example" "server\.env" >nul
    echo     Created server\.env from template - EDIT IT with your actual API keys
)

echo.
echo ============================================
echo   Setup Complete!
echo ============================================
echo   Quick Start:
echo   1. Activate:  %VENV_DIR%\Scripts\activate
echo   2. Run:       cd server ^& python run.py
echo.
echo   Advanced:
echo   - Test:       cd server ^& python -m pytest app/tests/ -v
echo   - Docker:     docker compose up --build
echo   - Guide:      Check postman_testing_guide.md for API testing
echo.
echo   REQUIRED KEYS (.env):
echo   - GEMINI_API_KEY
echo   - GROQ_API_KEY / DEEPSEEK_API_KEY (for fallback)
echo   - SUPABASE_URL / SUPABASE_SERVICE_KEY (for state tracking)
echo ============================================
