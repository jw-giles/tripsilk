@echo off
rem Runs the self-test and rebuild, then the attack lab, from C:\Tripsilk.
rem Double-click it: it asks Windows for administrator rights itself.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
echo [lab] Stopping Tripsilk to register the lab trip line...
taskkill /IM Tripsilk.exe /F >nul 2>&1
timeout /t 2 /nobreak >nul
go run ./cmd/tripsilk-lab -add-tripline
call "%~dp0update.bat" test
if errorlevel 1 (
  echo Build failed; lab skipped.
  pause
  exit /b 1
)
echo Waiting 20 seconds for Tripsilk to start...
timeout /t 20 /nobreak >nul
"%~dp0build\bin\tripsilk-lab.exe"
echo.
echo Done. Reports: tripsilk-selftest.txt and tripsilk-lab.txt in %~dp0
timeout /t 15
