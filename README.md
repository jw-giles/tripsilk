# Tripsilk

**Stop AI agents and AI-driven malware from using your PC as a foothold.**

You run AI agents that can open shells, read files and reach the internet.
That's the point of them, and it's also exactly what an attacker wants: one
poisoned web page or document, and a trusted agent starts working for someone
else. Antivirus can't help much, because the agent is legitimate, signed
software doing legitimate-looking things.

Tripsilk watches what those programs *do*, shows it in plain language, and
steps in when something crosses a line. It runs alongside Microsoft
Defender, which keeps doing virus detection.

> **Status: prototype (0.11.0), Windows 10/11 only.** There are no prebuilt
> downloads yet: the installer isn't code-signed, and Microsoft Defender's
> machine-learning flagged an earlier build as malware (a false positive
> being reported). Build it from source (see Quick build). Leave
> "Freeze automatically" off until the practice week in `RELEASE.md` is done.

## In one minute

- **Sees it as it happens.** Every program start, outgoing connection and
  DNS lookup comes from Windows' own event tracing, about 0.2 seconds after
  it happens (measured below). No driver.
- **Knows what an agent started.** A shell, a download tool or a Windows
  tool attackers abuse, launched by your AI app, is named with its full
  command. Known attack patterns are critical alerts.
- **Catches the phone-home.** A program with no reason to reach the Telegram
  bot API, Discord webhooks, paste sites, tunnels or attack callback services
  is flagged by name, even behind shared Cloudflare addresses.
- **Trip lines.** A decoy file nothing should touch. Touching it is a
  critical alert, and with automatic containment on, the program and
  everything it started are frozen and cut off from the internet.
- **Explains itself.** Each alert says what happened and why it matters in
  plain words, with the evidence a specialist needs one click away: process
  ID, path, SHA-256, the chain of programs that started it.
- **Sends nothing.** No account, no cloud, no telemetry. With the sensor
  running, Tripsilk counts its own network traffic and shows it: it should
  read "none".

## Measured, not claimed

From the self-test on Windows 11 (build 26200), October 2026:

| What | Seen after |
|---|---|
| A program starting, with the right parent and command line | 215 ms |
| A program exiting | 220 ms |
| An outgoing connection, with the right program and port | 220 ms |
| A DNS lookup, attributed to the program that made it | 219 ms |
| A non-Telegram program looking up the Telegram bot API | 218 ms |

Events lost in the run: none.

From the attack lab (`tripsilk-lab.exe`, a harmless simulated rogue agent),
same PC, October 17, from the action to the alert:

| Lab step | Caught after |
|---|---|
| Its first connection to an AI service | 186 ms (was 3,556 ms before the sensor triggered the check) |
| Encoded PowerShell started by the "agent" (critical) | 163 ms |
| Shell commands started by the "agent" | 213 ms |
| Telegram bot API contact | 138 ms |
| An edit to a trip-line file | under 1 ms |

## What it doesn't do

Read this before relying on it.

- **It doesn't stop "AI swarms" in general.** It protects one PC from being
  used as a foothold, a source of keys, or a worker.
- **Browser-based AI looks like you browsing.** An agent working through a
  web page, or AI requests sent through an ordinary cloud server, isn't
  told apart from you.
- **Kernel-level malware can hide from it.** Tripsilk runs in user mode.
- **Programs with their own encrypted DNS** (DNS over HTTPS) skip the DNS
  view; their connections are still seen.
- **It's a prototype** until the release gate in `RELEASE.md` is passed.

The dashboard always lists what isn't covered, live, under Protection.

## Everything it does

Defender keeps doing virus detection. Tripsilk adds:

- **Real-time sensor** (0.11): reads Windows' built-in event tracing for
  every process start and exit, every outgoing TCP connection, and every
  DNS lookup with the program that made it. No driver. A program an AI app
  starts and stops within milliseconds is still caught, by name and parent;
  its command line is read the moment it starts. If tracing can't start,
  Tripsilk falls back to checking every 2 to 5 seconds and the coverage
  list says so. If something stops the sensor while Tripsilk runs, that's a
  high alert.
- **Burst detector** (0.11): flags an AI app whose programs open 40
  shells or network tools within 10 seconds (compilers and build tools
  aren't counted), or reach 12 places they've never used before
  within 30 seconds: faster than a person at a keyboard. A host's many
  addresses count once; a connection by raw address counts by its network.
  Alert only: nothing is frozen for a burst. Needs the real-time sensor.
- **Weekly summary** (0.11): "Your week" on Home sums the event journal:
  events and program starts recorded, alerts by severity, what Tripsilk
  froze or suspended itself, what practice mode would have frozen, which AI
  apps alerted, and the most frequent alerts. Re-summed every 3 hours, or
  with Update.
- **Event Log copy** (0.11, off by default): Settings can copy every alert
  to the Windows Event Log, Application log, source `Tripsilk`, for tools
  that already collect Windows events. Event IDs: 1001 trip line, 1002
  ransomware shield, 1003 agent, 1004 burst, 1005 internet lock, 1006
  control channel, 1007 AI connection, 1008 AI service rule, 1009 Defender,
  1010 Tripsilk itself, 1099 other. Level: critical is Error, high and
  medium Warning, the rest Information. The text uses .NET's message file
  so Event Viewer shows it as written. Uninstalling removes the source.
- **Sysmon reading** (0.11): when Microsoft Sysmon is installed, Tripsilk
  reads its log every 2 seconds and saves its process-start (1), network
  (3) and DNS (22) events to the journal as `sysmon` records, with Sysmon's
  own field names. The SHA-256 Sysmon took when a program started becomes
  the alert's hash, and the alert says if the file on disk has changed
  since. Tripsilk never installs or configures Sysmon; which events and
  hashes exist depends on your Sysmon config.
- **What Claude Code said vs what it did** (0.11): every 5 minutes,
  Tripsilk reads Claude Code's session logs (`%USERPROFILE%\.claude\projects`)
  from the last day and matches each shell command they ask for with the
  shells Tripsilk saw Claude Code start. Shells that match nothing are
  listed on the Programs page. Shown, not alerted, until a week of use
  shows how much of Claude Code's own housekeeping lands there. When the
  log format isn't recognized, or nothing matches at all (Claude Code may
  pass commands another way), it says "can't compare" instead.
- **Internet lock per AI app** (0.11): Tripsilk learns the places each AI
  app and the programs it starts reach (by organization: Anthropic, GitHub,
  npmjs.org; by address network when no name is known). On its rule card,
  "Lock to these places" makes that the list. Reaching anywhere else
  freezes the app with everything it started, through the same containment
  as a trip line, so it's recorded rather than done in practice mode or
  with automatic freezing off. One alert per app and place per 10 minutes,
  with "Add to its list".
- **Event journal** (0.11): every event and alert as one JSON line in
  `C:\ProgramData\Tripsilk\events\`, for a specialist's own tools (jq,
  Splunk, a script). New file every 16 MB, 256 MB total at most, oldest
  deleted first. Command lines can carry passwords, so the folder is
  readable by Administrators and SYSTEM only. Loopback connections are left
  out.
- **Control channels** (0.11): a program with no reason to reaching the
  Telegram bot API, Discord or Slack webhooks, paste and file-drop sites,
  tunnel services (ngrok, Cloudflare quick tunnels, ...), attack callback
  catchers (webhook.site, interactsh, ...) or "what's my IP" lookups.
  Matched by domain name from the DNS lookup, so services behind shared
  Cloudflare addresses are told apart. The service's own app and browsers
  are exempt; "Allow for this app" covers your own bot or tunnel.

- **Plain alerts with evidence** (0.11): each alert says what happened and
  why it matters in one sentence each, with the recommended button first.
  "Show evidence" holds the technical account: process ID, program path,
  SHA-256, the chain of programs that started it, and the destination.
  "Check this program on VirusTotal" opens the file's page in your browser
  by its fingerprint; Tripsilk itself sends nothing.
- **First-run setup** (0.11): three screens on first start: approve the AI
  apps you use, create a trip line in one click (a small text file in
  `Documents\Archive`, or your profile folder when Documents is synced by
  OneDrive), and turn on Windows folder protection. Automatic freezing
  starts off; the manual buttons work from the start.
- **Automatic containment** (0.11, off by default): when a program opens a
  trip line, or the ransomware shield is confident, Tripsilk freezes it and
  every program it started and blocks its internet, then offers Resume all
  or End program. Until you turn on "Freeze automatically" in Settings (and
  practice mode is off), alerts say what it would have done instead.
- **Rule card per AI app** (0.11): on Programs, one card per AI app: which
  AI services it may use, programs it may start quietly, channels it may
  reach, and what always alerts regardless.
- **Its own cost** (0.11): Settings shows Tripsilk's processor share (now
  and peak), memory and disk use, measured every 10 seconds.
- **The web**: an orb-web map at the top of the dashboard. This PC is the
  hub; each strand is a type of program (AI, Developer, Browsers, Games,
  Chat, Cloud sync, System, Other), and each program sits on its strand,
  the ones needing action closest to the hub. AI services are diamonds at
  the rim. Approved is teal, not yet approved is amber, needs action is red
  (its line trembles), suspended is grey and dashed. Click or Tab to a
  program for details and Allow / Suspend / Resume. Everything on it is
  also in the lists below, for screen readers; motion stops when Windows'
  reduce-motion setting is on.
- **Eight eyes**: the header shows what Tripsilk is watching. Click it to
  see which eye is off and what turns it back on.
- **Ransomware shield**: watches your Documents, Desktop, Pictures and other
  folders for a burst of file changes far beyond normal use, and suspends the
  program writing the most. Suspension is instant and reversible, so
  encryption stops mid-run and a false positive is undone with Resume. With
  Practice mode on it only logs what it would suspend.
- **Windows folder protection**: shows whether Controlled Folder Access is on
  and turns it on in one click, the strongest built-in anti-ransomware block.
- **Response toolkit**: on a malware alert, Scan it (Defender custom scan),
  End program (confirmed, reversible actions preferred), and Disconnect
  internet (an emergency block of all outbound traffic, including Defender
  updates; the dashboard is local and keeps working; one click to restore).
- **All traffic, by type**: filter chips over the web (AI, Browsers,
  Games, Chat & calls, Cloud sync, Developer, System, Other) show every
  program's connections, not just AI. Programs launched by another networked
  program orbit it as satellites (a game under Steam). Destinations are
  grouped by organization ("Microsoft x12") using names from the Windows DNS
  cache. After a 3-day learning period, a program's first contact with a new
  organization glows for a day. Ordinary traffic never raises alerts.
- **Open to your network**: lists programs accepting incoming TCP
  connections; a new one open to the network raises an alert.
- **Service rules**: click an app on the web and "Lock to these
  services" to limit it to the AI services it uses now. A connection to
  any other AI service raises an alert and turns that link red, with
  one-click "Add to its rule" if it was intended. An assistant suddenly
  using a new AI service is a strong sign it is following someone else's
  instructions. v1 alerts only; blocking is planned (see Known limits).
- **AI traffic map** (IPv4 and IPv6): which programs on this PC are connected to AI services
  (OpenAI, Anthropic, Gemini, OpenRouter, Mistral, ...), plus local model
  runtimes (Ollama, llama.cpp, LM Studio, ...). Unknown programs raise an alert
  with Allow / Suspend / Block internet.
- **Key watch: pulled from the build in 0.8.1.** It named any program
  reading SSH keys, cloud logins, browser password and cookie stores or
  crypto wallets. Microsoft Defender flagged the 0.8.0 build as
  Trojan:Win32/LummaStealer.DO!MTB (a machine-learning verdict), almost
  certainly because the build carried a list of exactly where those
  credentials live. It returns after the false positive is reported to
  Microsoft and resolved; the code is kept in `internal/secrets`, which
  nothing builds in for now.
- **Tripwires**: you pick bait files that nothing should ever touch. Any change,
  rename or delete is a critical alert. With read detection on, programs that
  merely *open* a bait file are caught too, by name.
- **AI agent watch**: a hijacked agent is usually one you trust, so Tripsilk
  watches what AI-connected apps *do*:
  - programs they launch (shells, network tools, and signed Windows tools
    attackers abuse), with the full command line; known attack patterns
    such as encoded PowerShell or adding a Defender exclusion are critical
  - new tools (MCP servers) added to Claude Desktop, Claude Code, Cursor,
    VS Code or Windsurf, the way injected instructions give an agent
    lasting access
  - anything new set to run at startup: Run keys, Startup folders,
    scheduled tasks
  You can approve programs per app ("Allow for this app"); dangerous
  commands alert regardless.
- **Defender dashboard**: real-time and tamper protection, definition age,
  scan history, recent detections, one-click scans and updates.
- **Reversible containment first**: suspend/resume a process, block/unblock
  its internet access. Ending a program is manual and confirmed. Tripsilk never
  deletes files, and refuses to touch critical Windows processes.
- **Stays on**: closing the window hides it and protection keeps running;
  launching Tripsilk again brings it back. Important alerts show as Windows
  notifications, and critical ones bring the window forward. Optional
  start at sign-in (a scheduled task, since Windows won't auto-start admin
  apps from the Run key). "Quit Tripsilk" in Settings stops it.
- **Report for an AI helper**: "Copy report for an AI helper" puts a summary
  of alerts, AI apps, contained programs and coverage gaps on the clipboard
  for pasting into Claude or another assistant. Anything that came from
  programs on the PC (names, paths, command lines, Defender errors) is
  fenced off with its backticks neutralized, and the reader is told to
  treat it as evidence, never as instructions, so a malicious file name
  can't steer the helper. Your user folder is replaced with `%USERPROFILE%`.
- **Guarding its own settings**: Tripsilk runs as admin, so what it trusts
  must not be changeable by ordinary programs. Settings are saved through a
  randomly named temporary file (a file planted under a predictable name
  can't take its place), a change takes effect only once it's saved, and if
  anything else edits or deletes `config.json`, Tripsilk writes its own
  settings back within 30 seconds and raises a high alert. Folder locations
  and system tools (icacls, netsh, schtasks, PowerShell) come from Windows
  itself, not environment variables a normal program can change, and the
  start-at-sign-in task is defined by your account's SID and written to the
  settings folder rather than your temp folder.
- **Honest coverage**: the dashboard always lists what is *not* covered.

## Development workflow

The scripts assume the project lives at `C:\Tripsilk`. After each change,
from an admin terminal (Win+X, Terminal (Admin)):

```
C:\Tripsilk\update.bat
```

That stops the running Tripsilk, builds, and relaunches. It doesn't touch
git unless the folder holds an empty file named `.local-snapshots`; then it
also commits a local snapshot after each build, as an undo history.
`update.bat test` also runs the self-test first; its report lands in
`C:\Tripsilk\tripsilk-selftest.txt`.
`update.bat lab` runs the attack lab (below) once Tripsilk has started; its
report lands in `C:\Tripsilk\tripsilk-lab.txt`. Both reports contain your
Windows user name and are kept out of git by `.gitignore`.

## Attack lab

`build\bin\tripsilk-lab.exe` plays a harmless rogue AI agent against the
running Tripsilk and prints what was caught and how many milliseconds it
took: a connection to an AI service that sends nothing, a few
`cmd /c echo`, a burst of 50 `cmd /c exit` as fast as they run, a PowerShell encoded command that only prints a word, a
Telegram bot API lookup and empty connection, an edit to a lab trip
line, and a connection to a site off the lab's internet lock (locked by
`tripsilk-lab -add-tripline`). It reads the answers from Tripsilk's event journal, so it needs an
admin terminal. `build\lab\Tripsilk-Lab.wsb` does the same in a fresh
Windows Sandbox, installer included (see `build\lab\README.txt`).

## Quick build (Windows 10/11)

Double-click `build-exe.bat`. It installs anything missing (Go, Wails, NSIS,
through winget), then builds `build\bin\Tripsilk.exe` and
`build\bin\Tripsilk-amd64-installer.exe` and opens that folder. No admin
terminal needed to build; the app itself asks for admin when it runs.

## Build (Windows, from scratch, by hand)

1. Install Go 1.25+ from https://go.dev/dl
2. Install the Wails CLI:
   ```
   go install github.com/wailsapp/wails/v2/cmd/wails@v2.16.0
   ```
3. WebView2 ships with Windows 10/11. `wails doctor` confirms.
4. In this folder:
   ```
   go mod tidy
   wails build
   ```
5. Run `build\bin\Tripsilk.exe`. It asks for administrator rights. That's
   needed for suspend, firewall rules, audit policy and the Security log.

For live-reload UI work: `wails dev`.

## Self-test (run this first)

Before building the app, check that every Windows feature works on your
machine. This needs only Go, not Wails. From an **administrator** terminal in
this folder:

```
go run ./cmd/tripsilk-selftest
```

It checks process lookup, IPv4 and IPv6 connection tables, the Windows DNS
cache, the process tree (parent PIDs, creation times,
command lines), startup entries, AI app tool lists, the TCP table (with a real loopback connection),
AI provider DNS, Defender, the tripwire watcher (modify and rename on a temp
file), suspend/resume (on a throwaway child process), the protected-process
guard, and firewall block/unblock (on a program path that doesn't exist).
Everything it creates is cleaned up. Results print as PASS / FAIL / SKIP and
are saved to `tripsilk-selftest.txt`. Send that file back if anything fails.

Add `-toast` to show a test notification. To also test read detection, add `-audit`. That turns on Windows File System
auditing, which stays on afterwards (it's what read detection uses anyway).

## Installing

`C:\Tripsilk` is the workshop; the installed copy is what should protect the
PC day to day. The installer puts Tripsilk in `C:\Program Files\Tripsilk`, which
programs without admin rights can't change.

1. Once: `winget install NSIS.NSIS` (the installer builder).
2. `C:\Tripsilk\update.bat installer` builds `build\bin\Tripsilk-amd64-installer.exe`.
3. Run it. Settings in `C:\ProgramData\Tripsilk` are shared, so the installed
   copy picks up your bait files, approvals and rules.

Start at sign-in only works in the installed copy: a dev build lives in a
folder normal programs can change, and Windows would start it as admin.
Uninstalling runs `Tripsilk.exe --uninstall-cleanup` first, which resumes
anything Tripsilk froze, removes its firewall rules (including the emergency
internet block), removes the audit rules on bait files and deletes the
sign-in task. Settings are kept; delete `C:\ProgramData\Tripsilk` to remove
them. The result is written to `C:\ProgramData\Tripsilk\uninstall.log`.

The installer isn't code-signed yet, so Windows SmartScreen will warn
before running it.

## First run: start in practice mode

Turn on **Practice mode** (bottom of the dashboard) before anything else.
Tripsilk then records what it *would* suspend or block without doing it. Run
it for a few days, see what it flags, allow the apps you use with AI on
purpose, then switch practice mode off.

## Layout

```
main.go, app.go          Wails entry point and UI bindings (thin)
cmd/tripsilk-selftest/   Console self-test for all Windows code paths
cmd/tripsilk-lab/        Harmless attack simulator; reports catches and timings
build/lab/               Windows Sandbox config for the lab
frontend/dist/           Dashboard: index.html, style.css, app.js, web.js, fonts/ (no build step)
build/windows/           App manifest (requires administrator)
internal/engine          Alert bus, history, persisted config
internal/sensor          Real-time event tracing: process, TCP, DNS (ETW, no driver)
internal/journal         JSON Lines event journal with rotation and a size cap
internal/channels        Control-channel services (bot APIs, paste, tunnels) by domain
internal/netmap          AI traffic map: TCP table + provider IPs + local runtimes
internal/canary          Bait file registry, directory watcher, 4663 read auditing and audit rules
internal/secrets         Key watch (not built in since 0.8.1, see above)
internal/shield          Ransomware shield: burst detector, top-writer ranking, folder watch
internal/burst           Agent burst detector: programs started and new destinations per agent, by rate
internal/traffic         All-traffic view: categories, organizations, motherships, first-contact history
internal/agentguard      Agent watch: process tree, spawn classifier, MCP configs, startup entries
internal/defender        Defender status, detections, scans (PowerShell module)
internal/respond         Suspend/resume (ntdll), firewall block (netsh), safety checks
internal/service         Wires detectors, alerts and actions together
internal/win             Win32 helpers (stdlib syscall only, no x/sys)
```

Settings live in `%ProgramData%\Tripsilk\config.json`.

## Verification status

Done in a Linux build environment:

- All `internal/` packages: unit tests pass; `go vet` and a `GOOS=windows`
  build are clean.
- `main.go` / `app.go`: type-checked against a stub of the Wails API only.
  `wails build` on Windows is the real check.
- Dashboard: rendered in Chromium against mock data in each state, at
  desktop and phone widths.

0.11's sensor, control-channel and journal code is unit-tested here, with
the Windows structure sizes checked against the SDK; it has not run on
Windows yet. The self-test's sensor checks are the real test.

On Windows 11 (build 26200): the self-test passed 39/39 (read detection
skipped) and the lab caught 4 of 4 steps that ran, on 0.11.0 on October 17,
before the fixes from that day's code review. Those fixes are unit-tested
but haven't run on Windows yet; `RELEASE.md` tracks that.
`update.bat test -audit` adds the read-auditing checks, including that
removing an audit rule stops the events (last passed 29/29 on 0.8.0).
The self-test doesn't cover the ransomware shield firing on a real burst,
Disconnect/Reconnect, or End program; those need a deliberate manual run.

## Known limits

- **The internet lock freezes, it doesn't block.** Windows Firewall can't
  limit one app's family of programs to a list of sites, so the connection
  that trips the lock is made before the freeze, and its first packets may
  leave. Places are organizations: approving GitHub approves all of
  GitHub, and approving a cloud host (Amazon Web Services) approves
  everything hosted there.

- **Bursts are judged on speed alone.** Only shells and network tools count
  toward the program limit, so a burst of an attacker's own program isn't
  flagged for speed (its connections still count). An agent working below
  40 of those in 10 seconds and 12 new places in 30 seconds isn't flagged for speed,
  and a big build or install by an agent you asked can trip it. The limits
  are first guesses to be tuned on a week of real use.

- **Notifications show as "Windows PowerShell"** until Tripsilk has an
  installer that registers its own app identity.
- **Wails options.** Hide-on-close and single-instance use Wails v2.6+
  options (`OnBeforeClose`, `SingleInstanceLock`). If `wails build`
  complains about them, those field names are the first thing to check.
- **Rules cover AI services only, and alert rather than block.** Tripsilk
  only recognizes AI providers, so a locked app talking to an ordinary
  website isn't a violation. Blocking by address is unreliable because
  AI services share CDN addresses with other sites; enforcing rules
  needs per-hostname filtering (a local DNS or TLS-SNI layer).
- **Shared addresses.** Several AI APIs sit behind Cloudflare/Google front
  ends whose IPs also serve other sites. An AI traffic alert is a lead, not
  proof.
- **Browsers.** AI used through a website (chatgpt.com in Chrome) looks like
  ordinary browsing. A browser-based agent is not distinguished from you.
- **Change events don't name the process.** Windows' directory watcher
  doesn't report who changed a file. Read detection (auditing) does.
- **Synced folders.** OneDrive, Dropbox etc. open files to sync them, which
  trips read detection. Keep bait outside synced folders.
- **Fast programs.** With the real-time sensor every start is seen. A
  program that exits within a few milliseconds may be gone before its
  command line can be read; its name and parent are still recorded.
  Without the sensor, agent watch polls every 2 seconds and can miss it.
- **Silent only with the sensor.** With the real-time sensor running,
  Tripsilk sends nothing on the network: it learns AI service addresses
  from the DNS answers Windows hands other programs, and Settings shows its
  own network traffic as counted by the sensor (it should read "none").
  Without the sensor it falls back to looking about 40 AI service names up
  itself every 10 minutes (DNS queries only), and the coverage list says so.
- **Control channels need the sensor.** Without it only the Telegram bot
  API is checked (its addresses are Telegram's own); the rest share CDN
  addresses with ordinary sites. A webhook sent through a browser looks
  like the user browsing.
- **Config locations** for AI apps are taken from each product's docs and
  may move between versions. Missing files show as not found, not errors.
- **Ransomware shield is last-resort, not prevention.** It stops an attack
  mid-run after some files are already lost; Windows folder protection
  prevents it, so turn that on too. The shield can misfire on a legitimate
  mass-write (a big extract, a backup); because its only automatic action is
  a reversible suspend, a misfire is undone with Resume. It only suspends
  on its own when one program wrote clearly more than everything else (at
  least 1 MB and twice the runner-up) and isn't a Windows component;
  otherwise it lists the top writers for you to pick. Turn on Practice
  mode to have it log instead while you tune it.
- **End program and Disconnect are manual.** Tripsilk auto-suspends (reversible)
  but never ends a program or cuts the network on its own.
- **Settings are Tripsilk's.** Editing `config.json` by hand while Tripsilk runs
  gets reverted within 30 seconds (and alerts). Quit Tripsilk first.
- **The settings folder keeps Windows' default permissions.** Ordinary
  programs can add files to `C:\ProgramData\Tripsilk` but can't change the
  ones Tripsilk creates. A program that created that folder before Tripsilk was
  first installed would own it; locking the folder down is planned with the
  installer.
- **Dev builds can be replaced.** `C:\Tripsilk\build\bin` is writable by your
  normal account, so a program without admin rights could swap Tripsilk.exe.
  That's why only the installed copy can start at sign-in, and why the
  dashboard lists an uninstalled copy under "Not covered".
- **User mode only.** Anything with kernel access can hide from Tripsilk.
- **TCP only.** Connections and listeners are TCP. UDP traffic (QUIC,
  many games and calls) isn't in the traffic view; DNS lookups are still
  seen through the sensor.
- **Attacks that touch none of it.** Malware that never reaches an AI
  service, a control channel or a trip line, and starts nothing from an AI
  app, is Defender's job, not Tripsilk's.

## Roadmap

1. Windows shakedown and fixes
2. Rule enforcement: block a locked app's connections outside its rule
3. Protected secrets (key watch): built in 0.8.0, pulled in 0.8.1 pending
   the Defender false-positive report
4. ETW capture so no spawn is missed: done in 0.11 (sensor, journal,
   control channels, lab). Next: alerts on the sensor's connections
   directly instead of the 5-second table scan
5. Tray icon (needs Wails v3 or a small native helper)
6. Linux/VPS edition (eBPF)
7. Code signing (the installer exists since 0.9.2): the gate for anyone
   besides Jacob to run Tripsilk without SmartScreen warnings, and for
   notifications to show as Tripsilk. Then lock the settings folder at install.

## Licence

Copyright 2026 Jacob Giles. Licensed under the Apache License, Version 2.0;
see `LICENSE`. The fonts in `frontend/dist/fonts` are under the SIL Open
Font License (`frontend/dist/fonts/OFL.txt`).
