package canary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistry(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "Bait.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRegistry()
	if err := r.Add(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("missing file must be rejected (user supplies bait)")
	}
	if err := r.Add(dir); err == nil {
		t.Error("directory must be rejected")
	}
	if err := r.Add(f); err != nil {
		t.Fatal(err)
	}
	if !r.Has(strings.ToUpper(f)) {
		t.Error("lookup must be case-insensitive")
	}
	if d := r.Dirs(); len(d) != 1 || d[0] != dir {
		t.Errorf("dirs = %v", d)
	}
	r.Remove(f)
	if r.Has(f) || len(r.List()) != 0 {
		t.Error("remove failed")
	}
}

func TestIsSystemReader(t *testing.T) {
	if !IsSystemReader(`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe`) {
		t.Error("Defender must be treated as a system reader")
	}
	if IsSystemReader(`C:\Users\j\AppData\Roaming\x\helper.exe`) {
		t.Error("ordinary process must not be filtered")
	}
}

func TestCoalesce(t *testing.T) {
	cases := []struct {
		name string
		acts []uint32
		want EventKind
	}{
		{"edit in place", []uint32{ActModified, ActModified}, Modified},
		{"editor save-over (remove, add)", []uint32{ActRemoved, ActAdded, ActModified}, Replaced},
		{"rename temp onto path", []uint32{ActRenamedNew}, Replaced},
		{"remove then rename onto", []uint32{ActRemoved, ActRenamedNew}, Replaced},
		{"deleted", []uint32{ActRemoved}, Deleted},
		{"renamed away", []uint32{ActRenamedOld}, Renamed},
		{"nothing", nil, ""},
	}
	for _, c := range cases {
		if got := Coalesce(c.acts); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestParseAccessesAndBaitReads(t *testing.T) {
	one := []byte(`{"Object":"C:\\b\\Bait.txt","Proc":"C:\\x\\evil.exe","Pid":"0x1f4","Time":"2026-10-05T12:00:00.1234567Z"}`)
	acc, err := ParseAccesses(one)
	if err != nil || len(acc) != 1 || acc[0].PID != 500 || acc[0].When.IsZero() {
		t.Fatalf("single object: %+v %v", acc, err)
	}
	many := []byte(`[{"Object":"C:\\b\\Bait.txt","Proc":"C:\\x\\evil.exe","Pid":"0x10","Time":""},` +
		`{"Object":"C:\\b\\bait.txt","Proc":"C:\\aw\\Tripsilk.exe","Pid":"0x11","Time":""},` +
		`{"Object":"C:\\b\\Bait.txt","Proc":"C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe","Pid":"0x12","Time":""},` +
		`{"Object":"C:\\other.txt","Proc":"C:\\x\\evil.exe","Pid":"0x13","Time":""}]`)
	acc, err = ParseAccesses(many)
	if err != nil || len(acc) != 4 {
		t.Fatalf("array: %+v %v", acc, err)
	}
	reg := NewRegistry()
	reg.watches[key(`C:\b\Bait.txt`)] = Watch{Path: `C:\b\Bait.txt`}
	evs := BaitReads(acc, reg, `C:\aw\Tripsilk.exe`)
	if len(evs) != 1 || evs[0].PID != 16 {
		t.Fatalf("want only evil.exe's read: %+v", evs)
	}
	if acc, _ := ParseAccesses([]byte("  ")); acc != nil {
		t.Fatal("empty output is no events")
	}
}
