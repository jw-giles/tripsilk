package secrets

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverFindsStoresAndSkipsPublicFiles(t *testing.T) {
	home := t.TempDir()
	app := filepath.Join(home, "AppData", "Roaming")
	local := filepath.Join(home, "AppData", "Local")
	touch(t, filepath.Join(home, ".ssh", "id_ed25519"))
	touch(t, filepath.Join(home, ".ssh", "id_ed25519.pub"))
	touch(t, filepath.Join(home, ".ssh", "known_hosts"))
	touch(t, filepath.Join(home, ".ssh", "config"))
	touch(t, filepath.Join(home, ".aws", "credentials"))
	touch(t, filepath.Join(local, "Google", "Chrome", "User Data", "Default", "Login Data"))
	touch(t, filepath.Join(local, "Google", "Chrome", "User Data", "Profile 1", "Network", "Cookies"))
	touch(t, filepath.Join(app, "Mozilla", "Firefox", "Profiles", "abc.default", "logins.json"))
	os.MkdirAll(filepath.Join(home, ".ssh", "sub"), 0o755) // directories are not files

	items := Discover(Env{Home: home, AppData: app, LocalAppData: local})
	got := map[string]int{}
	for _, it := range items {
		got[it.Kind]++
		if filepath.Ext(it.Path) == ".pub" || filepath.Base(it.Path) == "known_hosts" || filepath.Base(it.Path) == "config" {
			t.Errorf("not a secret: %s", it.Path)
		}
	}
	want := map[string]int{"ssh": 1, "aws": 1, "chrome": 2, "firefox": 1}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s: got %d, want %d (%v)", k, got[k], n, items)
		}
	}
	if len(Discover(Env{})) != 0 {
		t.Error("empty roots must find nothing")
	}
}

func TestOwners(t *testing.T) {
	chrome, _ := KindByID("chrome")
	if !IsOwner(chrome, `C:\Program Files\Google\Chrome\Application\chrome.exe`) {
		t.Error("chrome owns its store")
	}
	if !IsOwner(chrome, `C:\Program Files\Google\Chrome\Application\130.0\elevation_service.exe`) {
		t.Error("files in Chrome's install folder own its store")
	}
	if IsOwner(chrome, `C:\Users\j\AppData\Local\Temp\chrome.exe.bin`) {
		t.Error("near-miss names must not match")
	}
	wallet, _ := KindByID("wallet")
	if !IsOwner(wallet, `C:\Program Files (x86)\Electrum\electrum-4.5.5.exe`) {
		t.Error("base-name globs should match versioned exe names")
	}
}

var t0 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func newTestAnalyzer(allowed func(string, string) bool) *Analyzer {
	a := NewAnalyzer(allowed)
	a.SetItems([]Item{
		{"ssh", `C:\Users\j\.ssh\id_ed25519`},
		{"aws", `C:\Users\j\.aws\credentials`},
		{"chrome", `C:\Users\j\AppData\Local\Google\Chrome\User Data\Default\Login Data`},
		{"firefox", `C:\Users\j\AppData\Roaming\Mozilla\Firefox\Profiles\x\logins.json`},
	})
	return a
}

func TestAnalyzerOwnersAndSystemAreQuiet(t *testing.T) {
	a := newTestAnalyzer(nil)
	quiet := []Read{
		{Path: `C:\Users\j\.ssh\id_ed25519`, Image: `C:\Windows\System32\OpenSSH\ssh.exe`, PID: 100, When: t0},
		{Path: `c:\users\j\appdata\local\google\chrome\user data\default\login data`, Image: `C:\Program Files\Google\Chrome\Application\chrome.exe`, PID: 101, When: t0},
		{Path: `C:\Users\j\.aws\credentials`, Image: `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe`, PID: 102, When: t0},
		{Path: `C:\Users\j\.aws\credentials`, Image: `C:\Windows\explorer.exe`, PID: 103, When: t0},
		{Path: `C:\Users\j\.aws\credentials`, Image: `System`, PID: 4, When: t0},
		{Path: `C:\Users\j\notes.txt`, Image: `C:\x\odd.exe`, PID: 105, When: t0},
	}
	for _, r := range quiet {
		if f := a.Observe(r); f != nil {
			t.Errorf("expected no finding for %s reading %s, got %+v", r.Image, r.Path, f)
		}
	}
}

func TestAnalyzerLevels(t *testing.T) {
	a := newTestAnalyzer(func(kind, image string) bool { return kind == "aws" && image == `C:\Backup\backup.exe` })
	if f := a.Observe(Read{Path: `C:\Users\j\.aws\credentials`, Image: `C:\Backup\backup.exe`, PID: 50, When: t0}); f != nil {
		t.Fatalf("allowed reader reported: %+v", f)
	}
	f := a.Observe(Read{Path: `C:\Users\j\.ssh\id_ed25519`, Image: `C:\Tools\node.exe`, PID: 60, When: t0, Agent: `C:\Tools\claude.exe`})
	if f == nil || f.Level != Agent {
		t.Fatalf("agent read: %+v", f)
	}
	f = a.Observe(Read{Path: `C:\Users\j\.aws\credentials`, Image: `C:\Temp\x.exe`, PID: 70, When: t0})
	if f == nil || f.Level != Unknown {
		t.Fatalf("unknown read: %+v", f)
	}
	// The same program and store again soon: no repeat.
	if f := a.Observe(Read{Path: `C:\Users\j\.aws\credentials`, Image: `C:\Temp\x.exe`, PID: 70, When: t0.Add(time.Minute)}); f != nil {
		t.Fatalf("repeat should be quiet: %+v", f)
	}
	// A second, different store within the window: the stealer pattern.
	f = a.Observe(Read{Path: `C:\Users\j\AppData\Local\Google\Chrome\User Data\Default\Login Data`, Image: `C:\Temp\x.exe`, PID: 70, When: t0.Add(90 * time.Second)})
	if f == nil || f.Level != Stealer || len(f.Kinds) != 2 {
		t.Fatalf("pattern: %+v", f)
	}
	// Outside the window, reads don't combine.
	b := newTestAnalyzer(nil)
	b.Observe(Read{Path: `C:\Users\j\.aws\credentials`, Image: `C:\Temp\y.exe`, PID: 80, When: t0})
	f = b.Observe(Read{Path: `C:\Users\j\.ssh\id_ed25519`, Image: `C:\Temp\y.exe`, PID: 80, When: t0.Add(5 * time.Minute)})
	if f == nil || f.Level != Unknown {
		t.Fatalf("reads minutes apart are separate: %+v", f)
	}
}

func TestBrowserImportIsLowAndNotAPattern(t *testing.T) {
	a := newTestAnalyzer(nil)
	edge := `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
	f := a.Observe(Read{Path: `C:\Users\j\AppData\Local\Google\Chrome\User Data\Default\Login Data`, Image: edge, PID: 90, When: t0})
	if f == nil || f.Level != Import {
		t.Fatalf("browser import: %+v", f)
	}
	f = a.Observe(Read{Path: `C:\Users\j\AppData\Roaming\Mozilla\Firefox\Profiles\x\logins.json`, Image: edge, PID: 90, When: t0.Add(time.Second)})
	if f == nil || f.Level != Import {
		t.Fatalf("second import is still an import, not the stealer pattern: %+v", f)
	}
	// A browser reading SSH keys is not an import.
	f = a.Observe(Read{Path: `C:\Users\j\.ssh\id_ed25519`, Image: edge, PID: 90, When: t0.Add(2 * time.Second)})
	if f == nil || f.Level != Unknown {
		t.Fatalf("browser reading SSH keys: %+v", f)
	}
}
