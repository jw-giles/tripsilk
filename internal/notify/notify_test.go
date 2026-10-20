package notify

import (
	"strings"
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	l := NewLimiter(20 * time.Second)
	t0 := time.Now()
	if ok, n := l.Allow(t0); !ok || n != 0 {
		t.Fatal("first toast must show")
	}
	if ok, _ := l.Allow(t0.Add(5 * time.Second)); ok {
		t.Fatal("burst not limited")
	}
	l.Allow(t0.Add(6 * time.Second))
	ok, n := l.Allow(t0.Add(25 * time.Second))
	if !ok || n != 2 {
		t.Fatalf("after gap: ok=%v suppressed=%d", ok, n)
	}
}

func TestClip(t *testing.T) {
	if Clip("a  b\n c", 10) != "a b c" {
		t.Fatal("whitespace not collapsed")
	}
	if got := Clip("abcdefghij", 5); got != "abcd…" {
		t.Fatalf("got %q", got)
	}
}

func TestTaskXMLKeepsRunning(t *testing.T) {
	x := TaskXML(`DESKTOP\\user`, `C:\\Tripsilk\\build\\bin\\Tripsilk.exe`)
	for _, want := range []string{
		"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
		"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
		"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
		"<RunLevel>HighestAvailable</RunLevel>",
		`<Command>C:\\Tripsilk\\build\\bin\\Tripsilk.exe</Command>`,
		`<UserId>DESKTOP\\user</UserId>`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("task XML missing %s", want)
		}
	}
	if !strings.Contains(TaskXML("a&b", `C:\\<x>`), "a&amp;b") {
		t.Error("XML special characters must be escaped")
	}
	b := UTF16LE("A")
	if len(b) != 4 || b[0] != 0xFF || b[1] != 0xFE || b[2] != 'A' || b[3] != 0 {
		t.Errorf("UTF-16LE with BOM: %v", b)
	}
}
