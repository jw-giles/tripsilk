@echo off
rem Tripsilk one-click build. Double-click this file; no admin needed.
rem Installs anything missing (Go, Wails, NSIS) and builds:
rem   build\bin\Tripsilk.exe                   the app
rem   build\bin\Tripsilk-amd64-installer.exe   the installer (if NSIS is available)
setlocal
cd /d "%~dp0"
title Tripsilk build

rem Where the tools land after a fresh install; this window's PATH doesn't
rem refresh on its own, so add them up front.
set "PATH=%PATH%;%ProgramFiles%\Go\bin;%USERPROFILE%\go\bin;%ProgramFiles(x86)%\NSIS;%ProgramFiles(x86)%\NSIS\Bin"

echo [1/4] Go
where go >nul 2>&1 && goto :have_go
call :winget_check || goto :fail
echo       Installing Go...
winget install -e --id GoLang.Go --accept-source-agreements --accept-package-agreements
where go >nul 2>&1 || goto :fail_go
:have_go
for /f "delims=" %%i in ('go env GOPATH') do set "PATH=%PATH%;%%i\bin"
go version

echo [2/4] Wails
where wails >nul 2>&1 && goto :have_wails
echo       Installing the Wails CLI (matches go.mod)...
go install github.com/wailsapp/wails/v2/cmd/wails@v2.16.0
where wails >nul 2>&1 || goto :fail
:have_wails

echo [3/4] NSIS (for the installer)
set "NSISFLAG=-nsis"
where makensis >nul 2>&1 && goto :have_nsis
call :winget_check || goto :no_nsis
echo       Installing NSIS...
winget install -e --id NSIS.NSIS --accept-source-agreements --accept-package-agreements
where makensis >nul 2>&1 && goto :have_nsis
:no_nsis
echo       NSIS not available; building the app only, no installer.
set "NSISFLAG="
:have_nsis

echo [4/4] Building (the first build downloads modules and takes a few minutes)...
wails build %NSISFLAG%
if errorlevel 1 goto :fail

echo.
echo Done. Output is in %CD%\build\bin
if defined NSISFLAG echo   Install with Tripsilk-amd64-installer.exe (SmartScreen will warn: More info, Run anyway).
echo   Or run Tripsilk.exe directly. Either way it asks for administrator rights.
start "" explorer "%CD%\build\bin"
pause
exit /b 0

:winget_check
where winget >nul 2>&1 && exit /b 0
echo       winget isn't available. Install "App Installer" from the Microsoft Store,
echo       or install the missing tool by hand (see README, "Build").
exit /b 1

:fail_go
echo       Go installed but this window can't see it yet. Close it and double-click
echo       build-exe.bat again.
goto :fail_end

:fail
echo.
echo Build failed. The error is above.
echo If it says Tripsilk.exe is in use, close Tripsilk and run this again.
:fail_end
pause
exit /b 1
