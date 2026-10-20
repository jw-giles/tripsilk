package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBusHistoryBoundedNewestFirst(t *testing.T) {
	b := NewBus(3)
	got := 0
	b.Subscribe(func(Alert) { got++ })
	for _, title := range []string{"a", "b", "c", "d"} {
		b.Publish(Alert{Title: title})
	}
	h := b.History()
	if len(h) != 3 || h[0].Title != "d" || h[2].Title != "b" {
		t.Fatalf("unexpected history: %+v", h)
	}
	if got != 4 {
		t.Fatalf("subscriber calls = %d", got)
	}
	if h[0].ID == "" || h[0].Time.IsZero() {
		t.Fatal("ID/time not filled")
	}
}

func TestStoreAllowPersists(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Allow(`C:\Apps\Agent.exe`); err != nil {
		t.Fatal(err)
	}
	_ = s.Allow(`c:\apps\agent.exe`) // duplicate, case-insensitive
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.IsAllowed(`C:\APPS\AGENT.EXE`) {
		t.Fatal("allow not persisted")
	}
	if n := len(s2.Get().AllowedProcesses); n != 1 {
		t.Fatalf("duplicates: %d", n)
	}
	_ = s2.Disallow(`C:\Apps\Agent.exe`)
	if s2.IsAllowed(`c:\apps\agent.exe`) {
		t.Fatal("disallow failed")
	}
}

// Regression: approving a child program used to wipe every service rule.
func TestAllowChildKeepsServiceRules(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetServiceRule(`C:\\x\\claude.exe`, []string{"Anthropic"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AllowChild(`C:\\x\\claude.exe`, "git.exe"); err != nil {
		t.Fatal(err)
	}
	if r, ok := s.ServiceRule(`C:\\x\\claude.exe`); !ok || len(r) != 1 || r[0] != "Anthropic" {
		t.Fatalf("service rule lost after AllowChild: %v %v", r, ok)
	}
}

func TestKeyAllow(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetServiceRule(`C:\a\app.exe`, []string{"OpenAI"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AllowKeyReader("ssh", `C:\Backup\B.exe`); err != nil {
		t.Fatal(err)
	}
	s.AllowKeyReader("ssh", `c:\backup\b.exe`) // duplicate, any case
	if !s.IsKeyReaderAllowed("ssh", `C:\BACKUP\b.exe`) || s.IsKeyReaderAllowed("aws", `C:\Backup\B.exe`) {
		t.Fatal("approval is per store and case-insensitive")
	}
	c := s.Get()
	if len(c.KeyAllow["ssh"]) != 1 || len(c.ServiceRules) != 1 {
		t.Fatalf("config: %+v", c)
	}
	c.KeyAllow["ssh"][0] = "mutated"
	if !s.IsKeyReaderAllowed("ssh", `C:\Backup\B.exe`) {
		t.Fatal("Get must return a copy")
	}
	s.AllowKeyReader("*", `C:\Tools\backup.exe`)
	if !s.IsKeyReaderAllowed("firefox", `C:\Tools\backup.exe`) {
		t.Fatal("* approves every store")
	}
	s.RemoveKeyAllow("*", `C:\Tools\backup.exe`)
	s.RemoveKeyAllow("ssh", `C:\Backup\B.exe`)
	if s.IsKeyReaderAllowed("ssh", `C:\Backup\B.exe`) || len(s.Get().KeyAllow) != 0 {
		t.Fatal("remove failed")
	}
}

func TestWriteFileAtomicIgnoresPlantedTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	planted := path + ".tmp" // the old fixed temp name
	if err := os.WriteFile(planted, []byte("attacker"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("ours")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "ours" {
		t.Fatalf("got %q", b)
	}
	if b, _ := os.ReadFile(planted); string(b) != "attacker" {
		t.Fatal("the planted file must not be reused")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Fatalf("temp file left behind: %v", ents)
	}
}

func TestVerifyRestoresTamperedSettings(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if tampered, _ := s.Verify(); tampered {
		t.Fatal("a fresh store with no file is not tampered")
	}
	if err := s.Allow(`C:\a\good.exe`); err != nil {
		t.Fatal(err)
	}
	if tampered, _ := s.Verify(); tampered {
		t.Fatal("Tripsilk's own write is not tampering")
	}
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"allowedProcesses":["c:\\evil\\x.exe"]}`), 0o600)
	tampered, err := s.Verify()
	if !tampered || err != nil {
		t.Fatalf("outside edit not caught: %v %v", tampered, err)
	}
	if s.IsAllowed(`C:\evil\x.exe`) || !s.IsAllowed(`C:\a\good.exe`) {
		t.Fatal("in-memory settings must win")
	}
	s2, _ := OpenStore(dir)
	if s2.IsAllowed(`C:\evil\x.exe`) || !s2.IsAllowed(`C:\a\good.exe`) {
		t.Fatal("restored file must hold Tripsilk's settings")
	}
	os.Remove(path)
	if tampered, _ := s.Verify(); !tampered {
		t.Fatal("deleting the settings is tampering")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("settings not rewritten after deletion")
	}
}

func TestFailedSaveChangesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Allow(`C:\a\one.exe`); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(dir) // saving now fails
	if err := s.Allow(`C:\a\two.exe`); err == nil {
		t.Fatal("save should fail")
	}
	if s.IsAllowed(`C:\a\two.exe`) || !s.IsAllowed(`C:\a\one.exe`) {
		t.Fatal("a change that wasn't saved must not take effect")
	}
}

func TestMigrateLegacyCopiesOnce(t *testing.T) {
	root := t.TempDir()
	oldDir, newDir := filepath.Join(root, ".awall"), filepath.Join(root, ".tripsilk")
	os.MkdirAll(oldDir, 0o700)
	os.WriteFile(filepath.Join(oldDir, "config.json"), []byte(`{"baitFiles":["C:\\b\\bait.txt"]}`), 0o600)
	os.WriteFile(filepath.Join(oldDir, "seen.json"), []byte(`{}`), 0o600)
	moved, err := MigrateLegacy(newDir)
	if err != nil || !moved {
		t.Fatalf("first run should copy: %v %v", moved, err)
	}
	s, _ := OpenStore(newDir)
	if c := s.Get(); len(c.BaitFiles) != 1 {
		t.Fatalf("settings not carried over: %+v", c)
	}
	if _, err := os.Stat(filepath.Join(oldDir, "config.json")); err != nil {
		t.Fatal("the old folder must be left alone")
	}
	// Tripsilk's own settings are never overwritten.
	s.Allow(`C:\a\x.exe`)
	if moved, _ := MigrateLegacy(newDir); moved {
		t.Fatal("must not copy again once Tripsilk has settings")
	}
	if moved, _ := MigrateLegacy(filepath.Join(root, "other")); moved {
		t.Fatal("only Tripsilk's folder names migrate")
	}
}
