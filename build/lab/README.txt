Tripsilk lab
============

tripsilk-lab.exe plays a harmless rogue AI agent and reports what Tripsilk
caught and how fast. Every action is benign: a connection to an AI service
that sends nothing, ten "cmd /c echo" commands, a PowerShell command that
only prints a word, a lookup and empty connection to the Telegram bot API,
and one line appended to a lab trip-line file.

On your PC (Tripsilk running, admin terminal):
    C:\Tripsilk\update.bat lab
or, after a build:
    C:\Tripsilk\build\bin\tripsilk-lab.exe

The first run creates tripsilk-lab-tripline.txt in your Documents folder.
Add it as a trip line in Tripsilk to include the trip-line step.

In a fresh Windows Sandbox (tests the installer too):
    1. Turn on Windows Sandbox once: Windows Features > Windows Sandbox.
    2. Build the installer: C:\Tripsilk\update.bat installer
    3. Double-click C:\Tripsilk\build\lab\Tripsilk-Lab.wsb
    The report appears in Notepad and in C:\Tripsilk\build\lab\out\.

If you cloned Tripsilk somewhere other than C:\Tripsilk, edit the two
HostFolder lines in Tripsilk-Lab.wsb first: Windows Sandbox needs full paths.

The lab's alerts are expected. Mark them handled in Tripsilk afterwards.
