# Contributing

Thanks for helping. Tripsilk is a security tool that runs as admin, so the
bar for changes is that they're honest, tested and small.

## Ground rules

1. **No claim without a measurement.** If a change adds detection, add a
   test that proves it, and a self-test or lab step when it touches Windows.
   The README's "Measured, not claimed" table only lists numbers from real
   runs.
2. **Say what isn't covered.** A new detection that has blind spots adds
   them to the coverage list in `internal/service/service.go` (`coverage`)
   and to the README's limits.
3. **Quiet beats loud.** Anything that alerts must stay near silent on a
   normal day of developer work. Anything that freezes or blocks starts in
   practice mode.
4. **Nothing leaves the PC.** No network calls from Tripsilk itself, no
   telemetry, no update checks. The sensor counts Tripsilk's own traffic;
   it must stay at zero.
5. **Standard library only** in `internal/` (no `golang.org/x/sys`). Windows
   calls go through `syscall` with struct sizes checked in tests.

## Building and testing

Windows 10 or 11, from an admin terminal in the project folder:

```
update.bat test        builds, runs the self-test, relaunches Tripsilk
build\bin\tripsilk-lab.exe   the attack lab, with Tripsilk running
```

Or double-click `run-checks.bat`, which does both and asks for admin rights
itself. Reports land in `tripsilk-selftest.txt` and `tripsilk-lab.txt`.

Unit tests run on any OS: `go test ./internal/...` (the Wails app itself
needs Windows). The sensor's parsers have replay tests built from real
Windows events in `internal/sensor/testdata`; after a Windows feature
update, re-record with `go run ./cmd/tripsilk-selftest -record` and add the
sample (it records only the self-test's own activity; replace your user
name in the bytes before committing).

## Writing for users

Alerts start with one plain sentence on what happened and one on why it
matters (`Summary`, `Why`), with one recommended action (`Do`). Technical
detail goes in `Detail` and `Evidence`. Never recommend Allow for a program
the user might not recognize.

## Security problems

Don't open a public issue: see `SECURITY.md`.
