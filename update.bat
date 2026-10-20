@echo off
rem Tripsilk update: stop the running copy, build, relaunch.
rem With a file named .local-snapshots in this folder, it also commits a
rem local git snapshot after each build (an undo history; never pushed).
rem Run from an admin terminal (Win+X, Terminal (Admin)):
rem     C:\Tripsilk\update.bat          build and launch
rem     C:\Tripsilk\update.bat test     also run the self-test first
rem     C:\Tripsilk\update.bat test -audit   also test read detection
rem     C:\Tripsilk\update.bat installer      also build the Windows installer (needs NSIS)
rem     C:\Tripsilk\update.bat lab            run the attack lab once Tripsilk has started
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo This needs an admin terminal: Win+X, then Terminal ^(Admin^).
  exit /b 1
)

echo [1/5] Stopping Tripsilk if it is running...
taskkill /IM Tripsilk.exe /F >nul 2>&1
rem Also the copy from before the rename to Tripsilk.
taskkill /IM aWall.exe /F >nul 2>&1

echo [2/5] Checking dependencies...
go mod tidy
if errorlevel 1 goto :fail

set "NSISFLAG="
if /i "%~1"=="installer" (
  rem NSIS's installer doesn't add itself to PATH.
  if exist "%ProgramFiles(x86)%\NSIS\Bin\makensis.exe" set "PATH=%PATH%;%ProgramFiles(x86)%\NSIS\Bin"
  if exist "%ProgramFiles(x86)%\NSIS\makensis.exe" set "PATH=%PATH%;%ProgramFiles(x86)%\NSIS"
  set "NSISFLAG=-nsis"
)

if /i "%~1"=="test" (
  echo [3/5] Running self-test...
  go run ./cmd/tripsilk-selftest -toast %2
) else (
  echo [3/5] Self-test skipped. Run "update.bat test" to include it.
)

echo [4/5] Building...
wails build %NSISFLAG%
if errorlevel 1 goto :fail
if defined NSISFLAG echo       Installer: %CD%\build\bin\ (the file ending in -installer.exe)
go build -o build\bin\tripsilk-lab.exe ./cmd/tripsilk-lab
if errorlevel 1 goto :fail

if exist ".local-snapshots" if exist ".git" (
  git add -A >nul 2>&1
  git commit -q -m "Tripsilk build %date% %time%" >nul 2>&1
  echo       Snapshot saved in git. Undo a bad update with: git log, then git checkout ^<id^> -- .
)

echo [5/5] Starting Tripsilk...
start "" "build\bin\Tripsilk.exe"
if /i "%~1"=="lab" (
  echo       Waiting 20 seconds for Tripsilk to start, then running the lab...
  timeout /t 20 /nobreak >nul
  "build\bin\tripsilk-lab.exe"
)
echo Done.
exit /b 0

:fail
echo.
echo Build failed. Copy the error above into the chat.
exit /b 1
