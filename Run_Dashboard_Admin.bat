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

net session >nul 2>&1
if "%ERRORLEVEL%"=="0" (
  echo Running with Administrator rights.
  "%PYTHON_EXE%" "%~dp0cyber_dashboard.py"
  set "EXIT_CODE=%ERRORLEVEL%"
  if not "%EXIT_CODE%"=="0" (
    echo.
    echo Dashboard exited with error code %EXIT_CODE%.
    pause
    exit /b %EXIT_CODE%
  )
  exit /b 0
)

echo Requesting Administrator rights...
set "ELEVATED_BAT=%TEMP%\cyber_dashboard_admin_%RANDOM%%RANDOM%.bat"
> "%ELEVATED_BAT%" echo @echo off
>> "%ELEVATED_BAT%" echo cd /d "%~dp0"
>> "%ELEVATED_BAT%" echo echo Cybersecurity Alert Dashboard running as Administrator.
>> "%ELEVATED_BAT%" echo "%PYTHON_EXE%" "%~dp0cyber_dashboard.py"
>> "%ELEVATED_BAT%" echo echo.
>> "%ELEVATED_BAT%" echo echo Dashboard closed. You may close this window.
>> "%ELEVATED_BAT%" echo pause

powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%ELEVATED_BAT%' -Verb RunAs"
if not "%ERRORLEVEL%"=="0" (
  echo.
  echo Failed to request Administrator rights.
  echo Right-click Run_Dashboard_Admin.bat and choose Run as administrator.
  pause
  exit /b 1
)
exit /b 0
