# Releasing Tripsilk

Nothing goes to anyone else's PC until every box below is ticked. This is
week 4 of the work schedule.

## 1. Gate: the build is proven

- [ ] `update.bat test` passes on the release build (38/38 on 0.11.0, Oct 17).
- [ ] `tripsilk-lab.exe` runs and its report shows each step caught, with
      times. (Oct 17, before the review fixes: 4 of 4 caught; the Telegram
      step was skipped by the half-hour alert cooldown. Rerun on the current
      build at least 30 minutes after the last lab run.)
- [ ] `update.bat test -audit`: read detection has only been skipped since
      0.8.0.
- [ ] A week of normal use with practice mode on, and the "would have
      frozen" notes reviewed: zero that would have frozen real work.
- [ ] Fresh Windows Sandbox: `build\lab\Tripsilk-Lab.wsb` installs, runs
      first-run setup and the lab, and uninstalling leaves nothing behind
      (`C:\ProgramData\Tripsilk\uninstall.log` says "Everything undone").

## Open review findings (Oct 17)

An independent review found 12 issues. All are fixed in code. **Leave
"Freeze automatically" off** until the containment fixes have run on
Windows (self-test and lab) and the practice week shows no false alarms.

Fixed (Oct 17, unit-tested; not yet run on Windows):

- New installs no longer start in practice mode (it disabled the manual
  Suspend and Block buttons).
- Old `aWall` settings are brought over only when Administrators or SYSTEM
  own the folder and files.
- Early and periodic scans no longer overlap.
- Programs on network shares aren't read for hashing; files over 256 MB say
  so instead of "hashing" forever.
- Real-time spawn alerts carry the parent chain.
- "Check on VirusTotal" opens the browser through Explorer, without admin
  rights.
- Setup wizard: one step per Next, approvals kept for apps that
  disconnected, a failed finish keeps the wizard open.
- Hash and "signed" verdicts are re-checked after 10 minutes even if size
  and time match; learned AI-service addresses expire after a day.
- The lab trip line moved from Public Documents (any account can change it)
  to the user's Documents.
- The report's "not covered" lines are fenced.
- Containment leaves the whole family alone when the root is protected
  (Explorer, Windows services), so a trip-line read by Explorer can't
  freeze the desktop.
- Containment checks the PID still belongs to the program the event named
  (same file, started no later than the event); a late trip-line read
  can't hit a recycled PID.
- A second trigger from the same program adds to the first undo record, so
  Resume all undoes both.
- Resume all only removes a firewall block containment added (a block you
  set stays), and keeps what it couldn't undo so it can be retried.
- Ransomware-shield hits are recorded in the practice results.

## 2. Microsoft Defender false-positive report

0.8.0 was flagged as `Trojan:Win32/LummaStealer.DO!MTB` (a machine-learning
verdict). File the report before release, not after a user hits it.

1. Build the exact release files: `update.bat installer`.
2. Go to https://www.microsoft.com/en-us/wdsi/filesubmission and sign in
   with a Microsoft account. Choose **Software developer**.
3. Submit `Tripsilk.exe`, then separately `Tripsilk-amd64-installer.exe`
   and `tripsilk-lab.exe`. Select "Incorrectly detected as malware" and
   name the detection if Defender shows one.
4. Paste this as the description (edit the version):

   > Tripsilk 0.11.0 is an open-source Windows security monitor that runs
   > alongside Microsoft Defender. It reads Windows event tracing (process,
   > TCP and DNS-Client providers), the TCP tables and the DNS cache, and
   > it watches user-chosen decoy files. It can suspend a process and add
   > Windows Firewall rules, only when the user asks or turns on automatic
   > containment. It makes no network connections of its own. Source:
   > <public repository URL>. tripsilk-lab.exe is its self-test simulator:
   > it runs harmless commands (cmd /c echo, a PowerShell command that
   > prints one word, a DNS lookup) so the monitor can be measured.

5. Keep the submission ID in this file. Results usually take days.

## 3. Code signing

Unsigned installers trigger a SmartScreen warning, and toasts show as
"Windows PowerShell" until Tripsilk has its own identity.

Route chosen: **Azure Artifact Signing** (formerly Trusted Signing),
about $9.99/month. Microsoft lists individual developers in the USA and
Canada as eligible. It does not give instant SmartScreen trust; reputation
builds as releases are signed with the same identity, so sign every
release from the first one. An OV certificate ($150 to $300 a year, key on
a hardware token) is the fallback if identity validation fails.
(Source: Microsoft, "Code signing options", updated 2026-08-29.)

- [ ] Azure account, Artifact Signing account and identity validation
      as an individual.
- [ ] Sign `Tripsilk.exe` and the installer in `update.bat installer`
      (signtool with the Artifact Signing dlib). Timestamp every signature.
- [ ] Then lock `C:\ProgramData\Tripsilk` at install (see README, Known
      limits).

## 4. Public repository

- [x] `.gitignore` keeps out `build/bin/`, `tripsilk-selftest.txt` and
      `tripsilk-lab.txt`: the reports contain the Windows user name.
- [x] Fresh repository from a clean copy (Oct 20). The workshop
      (`C:\Tripsilk`) keeps its private history, which has built binaries
      and a Windows user name in it. The public repository is a separate
      folder, `C:\Tripsilk-public`, filled only by `publish.bat`.
- [x] README's "Known limits" and the in-app "Not covered" list match
      (checked Oct 20).
- [x] Licence: Apache-2.0 (`LICENSE`).
- [ ] Repository under the Jacob Giles account.
- [ ] Turn on private vulnerability reporting (repository Settings >
      Code security), so `SECURITY.md`'s instructions work.

## 5. Ship

- [ ] Version bumped in `wails.json` and `internal/service/report.go`
      (a test fails if they differ).
- [ ] Signed installer attached to a GitHub release with its SHA-256.
