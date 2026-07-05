@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PYTHON_EXE="
for /f "delims=" %%P in ('where python 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%P"
if not defined PYTHON_EXE (
  echo Python was not found.
  echo Install Python 3.10+ from python.org or the Microsoft Store, then run this file again.
  pause
  exit /b 1
)

"%PYTHON_EXE%" "%~dp0cyber_dashboard.py"
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
  echo.
  echo Dashboard exited with error code %EXIT_CODE%.
  pause
  exit /b %EXIT_CODE%
)
