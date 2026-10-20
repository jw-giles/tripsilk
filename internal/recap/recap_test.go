package recap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tripsilk/internal/engine"
	"tripsilk/internal/journal"
)

func TestBuildFromRealJournal(t *testing.T) {
	dir := t.TempDir()
	j, err := journal.Open(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		j.Write("proc_start", map[string]any{"pid": i})
	}
	j.Write("tcp_connect", map[string]any{"pid": 1})
	j.Write("alert", engine.Alert{Severity: engine.SevHigh, Source: "burst", Title: "claude.exe ran commands faster than a person could", Process: `C:\x\claude.exe`})
	j.Write("alert", engine.Alert{Severity: engine.SevHigh, Source: "burst", Title: "claude.exe ran commands faster than a person could", Process: `C:\x\Claude.exe`})
	j.Write("alert", engine.Alert{Severity: engine.SevCritical, Source: "canary", Title: "Trip line opened by bad.exe",
		Detail: "bad.exe read C:\\bait.txt. Tripsilk froze bad.exe and 2 programs it started and blocked its internet within 12 ms."})
	j.Write("alert", engine.Alert{Severity: engine.SevHigh, Source: "allowlist", Title: "codex.exe reached a place outside its internet lock", Process: `C:\x\codex.exe`,
		Detail: "x. Practice: with automatic containment on, Tripsilk would have frozen codex.exe."})
	j.Write("alert", engine.Alert{Severity: engine.SevInfo, Source: "system", Title: "Rule removed"})
	j.Close()
	r := Build(dir, journal.Files(dir), time.Now().Add(-7*24*time.Hour), time.Now().Add(time.Second))
	if r.Events != 36 || r.Starts != 30 || r.Alerts["high"] != 3 || r.Alerts["critical"] != 1 || r.Alerts["info"] != 0 {
		t.Fatalf("%+v", r)
	}
	if len(r.Top) != 3 || r.Top[0].Count != 2 || len(r.Stopped) != 1 || r.Practice != 1 {
		t.Fatalf("top %+v stopped %+v practice %d", r.Top, r.Stopped, r.Practice)
	}
	if strings.Join(r.AIApps, "|") != `C:\x\Claude.exe|C:\x\codex.exe` && strings.Join(r.AIApps, "|") != `C:\x\claude.exe|C:\x\codex.exe` {
		t.Fatalf("apps %v", r.AIApps)
	}
	// A window after everything: empty, not an error.
	r = Build(dir, journal.Files(dir), time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
	if r.Events != 0 || len(r.Top) != 0 {
		t.Fatalf("future window: %+v", r)
	}
}

func TestOldFilesAndJunkSkipped(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events-20260101-000000.jsonl")
	os.WriteFile(p, []byte("not json\n{\"time\":\"bad\"}\n{\"type\":\"alert\"}\n"), 0o600)
	old := time.Now().Add(-30 * 24 * time.Hour)
	os.Chtimes(p, old, old)
	q := filepath.Join(dir, "events-20260102-000000.jsonl")
	os.WriteFile(q, []byte("not json\n{\"time\":\"bad\"}\n{\"type\":\"alert\"}\n"), 0o600)
	r := Build(dir, []string{p, q, filepath.Join(dir, "missing.jsonl")}, time.Now().Add(-time.Hour), time.Now())
	if r.Events != 0 || r.Partial {
		t.Fatalf("%+v", r)
	}
}
