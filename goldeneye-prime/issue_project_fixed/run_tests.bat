@echo off
REM Windows batch script to run tests for XXE vulnerability demonstration

echo ================================================
echo XML Document Parser - XXE Vulnerability Tests
echo ================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo [1/3] Checking Python installation...
python --version
echo.

echo [2/3] Installing dependencies...
pip install -q -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo Dependencies installed successfully.
echo.

echo [3/3] Running tests...
echo.
echo Expected Results (fixed variant):
echo   - Basic functionality tests: PASS
echo   - XXE security tests: PASS (blocked)
echo.
echo The parser is now hardened against XXE attacks.
echo ================================================
echo.

REM Run pytest with verbose output via python to avoid PATH issues
python -m pytest tests/ -v --tb=short

echo.
echo ================================================
echo Test execution completed.
echo.
echo To see detailed vulnerability analysis, run:
echo   pytest tests/test_xml_parser.py::TestXXEVulnerability -v --tb=long
echo.
echo For more information, see KNOWN_ISSUE.md
echo ================================================

pause
