package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/canary"
	"tripsilk/internal/engine"
	"tripsilk/internal/shield"
	"tripsilk/internal/sysmon"
	"tripsilk/internal/traffic"
)

// fakeResponse stands in for Windows' suspend/resume/firewall.
func fakeResponse(t *testing.T) (frozen map[uint32]bool, blocked map[string]bool) {
	frozen, blocked = map[uint32]bool{}, map[string]bool{}
	os, or, ob, ou := suspendProc, resumeProc, blockProg, unblockRule
	suspendProc = func(pid uint32, img string) error { frozen[pid] = true; return nil }
	resumeProc = func(pid uint32, img string) error { delete(frozen, pid); return nil }
	blockProg = func(img string) (string, error) { blocked[img] = true; return "Tripsilk block: " + img, nil }
	unblockRule = func(rule string) error {
		delete(blocked, strings.TrimPrefix(rule, "Tripsilk block: "))
		return nil
	}
	t.Cleanup(func() { suspendProc, resumeProc, blockProg, unblockRule = os, or, ob, ou })
	return
}

func familyService(t *testing.T) *Service {
	s, _ := New(t.TempDir())
	t0 := time.Now().Add(-time.Minute)
	s.ag.table = map[uint32]agentguard.Proc{
		10: {PID: 10, PPID: 1, Image: `C:\x\bad.exe`, Created: t0},
		11: {PID: 11, PPID: 10, Image: `C:\x\child.exe`, Created: t0.Add(time.Second)},
		12: {PID: 12, PPID: 11, Image: `C:\x\grandchild.exe`, Created: t0.Add(2 * time.Second)},
		13: {PID: 13, PPID: 10, Image: `C:\x\recycled.exe`, Created: t0.Add(-time.Hour)},
		20: {PID: 20, PPID: 1, Image: `C:\x\other.exe`, Created: t0},
	}
	return s
}

func TestTripLineReadContainsFamilyOnlyWhenEnabled(t *testing.T) {
	frozen, blocked := fakeResponse(t)
	s := familyService(t)
	// Fresh install: practice mode, nothing done, but the alert says what would be.
	s.onCanary(canary.Event{Kind: canary.Read, PID: 10, Process: `C:\x\bad.exe`, Path: `C:\bait.txt`})
	if len(frozen) != 0 || len(blocked) != 0 {
		t.Fatalf("practice mode acted: %v %v", frozen, blocked)
	}
	if a := s.Bus.History()[0]; !strings.Contains(a.Detail, "would have frozen bad.exe and 2 programs") {
		t.Fatalf("practice note: %s", a.Detail)
	}
	// Practice off but containment not turned on: still nothing.
	_ = s.SetDryRun(false)
	s.onCanary(canary.Event{Kind: canary.Read, PID: 10, Process: `C:\x\bad.exe`, Path: `C:\bait.txt`})
	if len(frozen) != 0 {
		t.Fatal("acted without automatic containment on")
	}
	_ = s.SetAutoContain(true)
	s.onCanary(canary.Event{Kind: canary.Read, PID: 10, Process: `C:\x\bad.exe`, Path: `C:\bait.txt`})
	if !frozen[10] || !frozen[11] || !frozen[12] || frozen[13] || frozen[20] || !blocked[`C:\x\bad.exe`] {
		t.Fatalf("frozen %v blocked %v", frozen, blocked)
	}
	var a engine.Alert
	for _, x := range s.Bus.History() {
		if x.Source == "canary" {
			a = x
			break
		}
	}
	if a.Actions[0] != "resumeall" || !strings.Contains(a.Detail, "froze bad.exe and 2 programs") {
		t.Fatalf("alert: %+v", a)
	}
	if err := s.ResumeAll(10); err != nil || len(frozen) != 0 || len(blocked) != 0 {
		t.Fatalf("resume all: %v %v %v", err, frozen, blocked)
	}
	if err := s.ResumeAll(10); err == nil {
		t.Fatal("second resume all accepted")
	}
}

func TestContainmentReportsWhatFailed(t *testing.T) {
	frozen, _ := fakeResponse(t)
	suspendProc = func(pid uint32, img string) error {
		if pid == 11 {
			return errors.New("access denied")
		}
		frozen[pid] = true
		return nil
	}
	s := familyService(t)
	_ = s.SetDryRun(false)
	_ = s.SetAutoContain(true)
	r := s.contain(10, `C:\x\bad.exe`, time.Now())
	if r.frozen != 2 || len(r.failed) != 1 || !strings.Contains(containNote(`C:\x\bad.exe`, r), "access denied") {
		t.Fatalf("%+v", r)
	}
}

func TestCPUShare(t *testing.T) {
	if got := cpuShare(500*time.Millisecond, 10*time.Second, 4); got < 1.24 || got > 1.26 {
		t.Errorf("got %v, want 1.25", got)
	}
	if cpuShare(time.Second, 0, 4) != 0 || cpuShare(-time.Second, time.Second, 4) != 0 {
		t.Error("edge cases")
	}
}

func TestDiskUsageCountsDataDir(t *testing.T) {
	s, _ := New(t.TempDir())
	_ = s.SetToasts(true) // writes the settings file
	s.sampleUsage()
	if s.Snapshot().Usage.DiskMB <= 0 {
		t.Error("settings file not counted")
	}
}

func TestPracticeFreezesAreRecordedForReview(t *testing.T) {
	frozen, _ := fakeResponse(t)
	s := familyService(t)
	for i := 0; i < 55; i++ {
		s.contain(10, `C:\x\bad.exe`, time.Now())
	}
	w := s.Snapshot().WouldFreeze
	if len(frozen) != 0 || len(w) != 50 || w[49].Image != `C:\x\bad.exe` || w[49].Tree != 3 {
		t.Fatalf("frozen %v, record %d %+v", frozen, len(w), w[len(w)-1])
	}
	// Live containment isn't a practice record.
	_ = s.SetDryRun(false)
	_ = s.SetAutoContain(true)
	s.contain(20, `C:\x\other.exe`, time.Now())
	if w := s.Snapshot().WouldFreeze; w[len(w)-1].Image == `C:\x\other.exe` {
		t.Fatal("live containment recorded as practice")
	}
}

func TestFirstTimeDestinationsForAIAppsOnly(t *testing.T) {
	s, _ := New(t.TempDir())
	_ = s.store.Allow(`C:\x\claude.exe`)
	now := time.Now()
	apps := []traffic.App{
		{Key: `c:\x\claude.exe`, Links: []traffic.Link{{Org: "Example Docs", New: true}, {Org: "Anthropic", New: true, AI: true}, {Org: "GitHub"}}},
		{Key: `c:\x\node.exe`, Mothership: `c:\x\claude.exe`, Links: []traffic.Link{{Org: "npm", New: true}}},
		{Key: `c:\x\game.exe`, Links: []traffic.Link{{Org: "Steam", New: true}}},
	}
	s.mu.Lock()
	s.recordFirstsLocked(apps, now)
	s.recordFirstsLocked(apps, now.Add(time.Hour)) // a repeat keeps the first time
	s.mu.Unlock()
	f := s.Snapshot().FirstDests
	got := map[string]time.Time{}
	for _, x := range f[`c:\x\claude.exe`] {
		got[x.Org] = x.Time
	}
	if len(f) != 1 || len(got) != 2 || !got["Example Docs"].Equal(now) || got["npm"].IsZero() {
		t.Fatalf("firsts: %+v", f)
	}
	s.mu.Lock()
	s.recordFirstsLocked(nil, now.Add(8*24*time.Hour))
	s.mu.Unlock()
	if len(s.Snapshot().FirstDests) != 0 {
		t.Fatal("week-old entries kept")
	}
	for _, a := range s.Bus.History() {
		if a.Severity != engine.SevInfo {
			t.Fatalf("first-time destinations must not alert: %+v", a)
		}
	}
}

func TestNetworkPathsAreNotRead(t *testing.T) {
	for p, want := range map[string]bool{
		`\\server\share\x.exe`: true, `\\?\UNC\server\share\x.exe`: true, `//server/share/x.exe`: true,
		`C:\x\y.exe`: false, `\\?\C:\x\y.exe`: false, `\\.\pipe\x`: false, ``: false,
	} {
		if got := isNetworkPath(p); got != want {
			t.Errorf("isNetworkPath(%q) = %v, want %v", p, got, want)
		}
	}
	s, _ := New(t.TempDir())
	s.Bus.Publish(engine.Alert{Source: "x", Severity: engine.SevHigh, Process: `\\attacker\share\x.exe`})
	if e := s.Bus.History()[0].Evidence; e == nil || e.SHA256 != "" || !strings.Contains(e.HashNote, "network share") {
		t.Fatalf("evidence %+v", e)
	}
}

func liveContain(t *testing.T) (*Service, map[uint32]bool, map[string]bool) {
	frozen, blocked := fakeResponse(t)
	s := familyService(t)
	_ = s.SetDryRun(false)
	_ = s.SetAutoContain(true)
	return s, frozen, blocked
}

// Item 1: everything the user opened is a child of Explorer.
func TestProtectedRootFreezesNothing(t *testing.T) {
	s, frozen, blocked := liveContain(t)
	t0 := time.Now().Add(-time.Hour)
	s.ag.table[30] = agentguard.Proc{PID: 30, PPID: 1, Image: `C:\Windows\explorer.exe`, Created: t0}
	s.ag.table[31] = agentguard.Proc{PID: 31, PPID: 30, Image: `C:\x\editor.exe`, Created: t0.Add(time.Minute)}
	r := s.contain(30, `C:\Windows\explorer.exe`, time.Now())
	if len(frozen) != 0 || len(blocked) != 0 || r.frozen != 0 {
		t.Fatalf("froze %v blocked %v", frozen, blocked)
	}
	if n := containNote(`C:\Windows\explorer.exe`, r); !strings.Contains(n, "nothing it started was frozen") {
		t.Fatalf("note: %s", n)
	}
}

// Item 2: a late event must not hit whatever got the PID since.
func TestRecycledPIDNotContained(t *testing.T) {
	s, frozen, blocked := liveContain(t)
	// The table's PID 10 is bad.exe, but the event named another program.
	r := s.contain(10, `C:\x\gone.exe`, time.Now())
	// bad.exe started after the event: same image, newer process.
	r2 := s.contain(10, `C:\x\bad.exe`, time.Now().Add(-2*time.Minute))
	if len(frozen) != 0 || len(blocked) != 0 || r.frozen+r2.frozen != 0 {
		t.Fatalf("froze %v blocked %v", frozen, blocked)
	}
	if !strings.Contains(containNote(`C:\x\gone.exe`, r), "belongs to another program") {
		t.Fatalf("note: %s", containNote(`C:\x\gone.exe`, r))
	}
	// Not in the table: Windows is asked; an exited program is left alone.
	old := imagePath
	imagePath = func(uint32) string { return "" }
	defer func() { imagePath = old }()
	if r := s.contain(99, `C:\x\late.exe`, time.Now()); r.frozen != 0 || len(frozen) != 0 {
		t.Fatal("contained a PID with no program")
	}
	// Practice doesn't record a recycled PID either.
	_ = s.SetDryRun(true)
	s.contain(10, `C:\x\gone.exe`, time.Now())
	if len(s.Snapshot().WouldFreeze) != 0 {
		t.Fatal("practice recorded the wrong program")
	}
}

// Item 3: a second trigger must not lose the first record.
func TestRepeatContainmentStillFullyUndone(t *testing.T) {
	s, frozen, blocked := liveContain(t)
	s.contain(10, `C:\x\bad.exe`, time.Now())
	// The program starts another child, then trips again.
	s.ag.table[14] = agentguard.Proc{PID: 14, PPID: 10, Image: `C:\x\late.exe`, Created: time.Now()}
	s.contain(10, `C:\x\bad.exe`, time.Now())
	if !frozen[10] || !frozen[11] || !frozen[12] || !frozen[14] {
		t.Fatalf("frozen %v", frozen)
	}
	if err := s.ResumeAll(10); err != nil || len(frozen) != 0 || len(blocked) != 0 {
		t.Fatalf("resume all: %v frozen %v blocked %v", err, frozen, blocked)
	}
}

// Item 4: the user's own block stays; a failed undo can be retried.
func TestResumeAllKeepsUserBlockAndRetries(t *testing.T) {
	s, frozen, blocked := liveContain(t)
	if err := s.Block(`C:\x\bad.exe`); err != nil {
		t.Fatal(err)
	}
	fail := true
	resumeProc = func(pid uint32, img string) error {
		if pid == 11 && fail {
			return errors.New("access denied")
		}
		delete(frozen, pid)
		return nil
	}
	s.contain(10, `C:\x\bad.exe`, time.Now())
	if err := s.ResumeAll(10); err == nil || !frozen[11] {
		t.Fatalf("expected a partial undo: %v %v", err, frozen)
	}
	fail = false
	if err := s.ResumeAll(10); err != nil || len(frozen) != 0 {
		t.Fatalf("retry: %v %v", err, frozen)
	}
	if !blocked[`C:\x\bad.exe`] {
		t.Fatal("Resume all removed the user's own block")
	}
}

// Item 5: ransomware-shield hits count toward the week of practice results.
func TestShieldHitsReachThePracticeRecord(t *testing.T) {
	frozen, _ := fakeResponse(t)
	s := familyService(t)
	_ = s.SetDryRun(true)
	s.respondToBurst(shield.Writer{PID: 10, Image: `C:\x\bad.exe`, Bytes: 50 << 20}, 40, `C:\Users\u\Documents`)
	w := s.Snapshot().WouldFreeze
	if len(frozen) != 0 || len(w) != 1 || w[0].Image != `C:\x\bad.exe` || w[0].Tree != 3 {
		t.Fatalf("frozen %v record %+v", frozen, w)
	}
	// Practice off, containment off: the old single suspend, and still recorded.
	_ = s.SetDryRun(false)
	s.respondToBurst(shield.Writer{PID: 10, Image: `C:\x\bad.exe`, Bytes: 50 << 20}, 40, `C:\Users\u\Documents`)
	if !frozen[10] || frozen[11] || len(s.Snapshot().WouldFreeze) != 2 {
		t.Fatalf("frozen %v record %d", frozen, len(s.Snapshot().WouldFreeze))
	}
}

func TestEventLogSettingNotSavedWhenItFails(t *testing.T) {
	s, _ := New(t.TempDir())
	s.startEventLog()
	if err := s.SetEventLog(true); err == nil {
		t.Skip("event log available here")
	}
	if s.store.Get().EventLogCopy || s.Snapshot().EventLog.On {
		t.Fatal("setting saved although the event source couldn't be registered")
	}
	if err := s.SetEventLog(false); err != nil || s.Snapshot().EventLog.Open {
		t.Fatalf("off: %v", err)
	}
}

func TestSysmonHashIsEvidence(t *testing.T) {
	s, _ := New(t.TempDir())
	s.sm.hashes = sysmon.NewHashes(16)
	sum := strings.Repeat("ab", 32)
	s.onSysmon([]sysmon.Event{{ID: 1, PID: 77, Image: `C:\x\bad.exe`, SHA256: sum}}, nil)
	s.Bus.Publish(engine.Alert{Severity: engine.SevHigh, Source: "x", PID: 77, Process: `C:\x\bad.exe`})
	e := s.Bus.History()[0].Evidence
	if e == nil || e.SHA256 != sum || !strings.Contains(e.HashNote, "Sysmon") {
		t.Fatalf("evidence %+v", e)
	}
	// Same PID, another program: not used.
	s.Bus.Publish(engine.Alert{Severity: engine.SevHigh, Source: "x", PID: 77, Process: `C:\x\other.exe`})
	if e := s.Bus.History()[0].Evidence; e != nil && e.SHA256 == sum {
		t.Fatal("hash of a reused PID used")
	}
	if st := s.sysmonStatus(); st.Events != 1 {
		t.Fatalf("status %+v", st)
	}
}
