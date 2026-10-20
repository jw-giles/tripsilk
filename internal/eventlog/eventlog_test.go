package eventlog

import (
	"strings"
	"testing"
	"time"

	"tripsilk/internal/engine"
	"tripsilk/internal/evidence"
)

func TestTextAndMapping(t *testing.T) {
	a := engine.Alert{ID: "abc", Time: time.Date(2026, 10, 17, 1, 2, 3, 0, time.UTC), Severity: engine.SevCritical, Source: "canary",
		Title: "Trip line opened by bad.exe", Summary: "bad.exe opened a trip line.", Why: "Nothing should.", Detail: "Detail here.",
		Process: `C:\x\bad.exe`, PID: 7, Evidence: &engine.Evidence{SHA256: "ab12", Chain: []evidence.Link{{PID: 7, Image: `C:\x\bad.exe`}, {PID: 1, Image: `C:\x\parent.exe`}}}}
	txt := Text(a)
	for _, want := range []string{"Trip line opened by bad.exe\r\n", "bad.exe opened a trip line. Nothing should.", "PID: 7\r\n",
		"SHA-256: ab12", "Parent 1: C:\\x\\parent.exe (PID 1)", "Alert ID: abc", "Time: 2026-10-17T01:02:03.000Z"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "Channel:") {
		t.Error("empty fields printed")
	}
	if LevelOf(engine.SevCritical) != Error || LevelOf(engine.SevHigh) != Warning || LevelOf(engine.SevLow) != Information {
		t.Error("levels")
	}
	if IDOf("canary") != 1001 || IDOf("nope") != OtherID {
		t.Error("ids")
	}
	long := Text(engine.Alert{Detail: strings.Repeat("x", 100000)})
	if len(long) > maxText+20 || !strings.HasSuffix(long, "(cut short)") {
		t.Errorf("long text %d", len(long))
	}
	if stripNUL("a\x00b") != `a\0b` {
		t.Error("NUL")
	}
}
