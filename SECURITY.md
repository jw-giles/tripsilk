# Security policy

Tripsilk runs with administrator rights and watches other programs, so a
flaw in it can matter more than a flaw in an ordinary app. Thank you for
reporting one privately.

## How to report

Use GitHub's private vulnerability reporting on this repository
(**Security** tab > **Report a vulnerability**). Please don't open a public
issue for a security problem: it tells attackers before users can update.

Include what you can:

- Tripsilk version (Settings, or `wails.json`) and Windows build (`winver`)
- What an attacker needs first (a normal user account? admin? a file on
  the PC?) and what they get
- Steps to reproduce, or a proof of concept that does no harm

## What to expect

Tripsilk is maintained by one person. Reports are read within a few days.
A confirmed issue gets a fix and a release note crediting you, unless you'd
rather not be named. If a fix needs longer than 90 days, you'll be told why.

## In scope

The kinds of problems that matter most:

- **Privilege escalation:** an ordinary program using Tripsilk (which runs
  as admin) to do something admin-only: writing to a protected place,
  starting a program as admin, changing Tripsilk's settings or files.
- **Blinding Tripsilk:** stopping its sensor, hiding a program from it,
  editing its approvals, or getting a program exempted that shouldn't be,
  without the coverage list or an alert saying so.
- **Steering the AI-helper report:** text from a program (a file name, a
  command line) that escapes its fenced block in "Copy report for an AI
  helper" and reads as instructions.
- **Leaking what Tripsilk sees:** the event journal or settings becoming
  readable by a non-admin account, or Tripsilk sending anything over the
  network itself.
- **Wrong containment:** Tripsilk freezing or blocking a program that
  didn't trigger it, or failing to undo a freeze with Resume all.

## Out of scope

Listed in the README under "What it doesn't do" and in the app under "Not
covered": attacks with kernel-level access, AI used through a browser,
traffic through ordinary cloud services, and anything that never touches a
trip line, an AI service or a watched behaviour. A report that something in
those areas goes unseen is a known limit, not a vulnerability. Ideas for
narrowing them are still welcome as ordinary issues.
