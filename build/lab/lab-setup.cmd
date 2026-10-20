@echo off
rem Runs inside Windows Sandbox (see Tripsilk-Lab.wsb). Installs Tripsilk
rem fresh with practice mode on, waits for it to start, runs the lab.
if not exist C:\lab\out mkdir C:\lab\out
C:\lab-bin\tripsilk-lab.exe -sandbox-setup > C:\lab\out\setup.txt 2>&1
echo Installing Tripsilk... >> C:\lab\out\setup.txt
start /wait "" C:\lab-bin\Tripsilk-amd64-installer.exe /S
start "" "C:\Program Files\Tripsilk\Tripsilk.exe"
echo Waiting 30 seconds for Tripsilk to start... >> C:\lab\out\setup.txt
timeout /t 30 /nobreak > nul
cd /d C:\lab\out
C:\lab-bin\tripsilk-lab.exe >> C:\lab\out\setup.txt 2>&1
start notepad C:\lab\out\tripsilk-lab.txt
