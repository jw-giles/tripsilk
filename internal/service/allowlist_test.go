package service

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/engine"
	"tripsilk/internal/sensor"
)

func lockAlerts(s *Service) (out []engine.Alert) {
	for _, a := range s.Bus.History() {
		if a.Source == "allowlist" {
			out = append(out, a)
		}
	}
	return
}

// reach makes pid look up host and connect to it.
func reach(s *Service, pid uint32, host string, ip [4]byte) {
	a := netip.AddrFrom4(ip)
	if host != "" {
		s.onSensor(sensor.Event{Kind: sensor.DNS, PID: pid, Name: host, Answers: []netip.Addr{a}})
	}
	s.onSensor(sensor.Event{Kind: sensor.Connect, PID: pid, Remote: netip.AddrPortFrom(a, 443)})
}

func lockService(t *testing.T) *Service {
	s := burstService(t)
	s.ag.table[11] = agentguard.Proc{PID: 11, PPID: 10, Image: `C:\x\node.exe`, Created: time.Now()}
	s.ag.table[12] = agentguard.Proc{PID: 12, PPID: 11, Image: `C:\x\helper.exe`, Created: time.Now()}
	s.ag.table[50] = agentguard.Proc{PID: 50, PPID: 1, Image: `C:\x\browser.exe`, Created: time.Now()}
	return s
}

func TestInternetLockLearnsThenLocks(t *testing.T) {
	frozen, _ := fakeResponse(t)
	s := lockService(t)
	if err := s.LockDests(`C:\x\claude.exe`); err == nil {
		t.Fatal("locked with nothing learned")
	}
	reach(s, 10, "api.anthropic.com", [4]byte{160, 79, 104, 10})
	reach(s, 11, "registry.npmjs.org", [4]byte{104, 16, 0, 1})
	reach(s, 11, "github.com", [4]byte{140, 82, 112, 3})
	reach(s, 50, "example.com", [4]byte{93, 184, 216, 34}) // not the agent's
	used := s.store.Get().DestUsed[`c:\x\claude.exe`]
	if strings.Join(used, ",") != "Anthropic,npmjs.org,GitHub" {
		t.Fatalf("learned %v", used)
	}
	if err := s.LockDests(`C:\x\Claude.exe`); err != nil {
		t.Fatal(err)
	}
	// On the list, by a different server of the same organization: fine.
	reach(s, 12, "codeload.github.com", [4]byte{140, 82, 113, 9})
	if a := lockAlerts(s); len(a) != 0 {
		t.Fatalf("allowed place alerted: %+v", a)
	}
	// Off the list, automatic freezing off: alert and a practice record.
	reach(s, 12, "paste.example", [4]byte{45, 1, 2, 3})
	a := lockAlerts(s)
	if len(a) != 1 || a[0].PID != 10 || a[0].Dest != "paste.example" || a[0].Do != "suspend" || len(frozen) != 0 {
		t.Fatalf("alerts %+v frozen %v", a, frozen)
	}
	if !strings.Contains(a[0].Summary, "helper.exe, running under claude.exe,") {
		t.Fatalf("summary: %s", a[0].Summary)
	}
	if w := s.Snapshot().WouldFreeze; len(w) != 1 || w[0].Tree != 3 {
		t.Fatalf("practice record %+v", w)
	}
	// The same place again within the quiet period: no second alert.
	reach(s, 12, "paste.example", [4]byte{45, 1, 2, 3})
	if len(lockAlerts(s)) != 1 {
		t.Fatal("repeat alerted")
	}
	// Learning stops at the lock.
	if used := s.store.Get().DestUsed[`c:\x\claude.exe`]; len(used) != 3 {
		t.Fatalf("learned while locked: %v", used)
	}
	// Raw address, no name: its network is the place.
	reach(s, 11, "", [4]byte{203, 0, 113, 7})
	if a := lockAlerts(s); len(a) != 2 || a[0].Dest != "203.0.113.0/24" {
		t.Fatalf("raw address: %+v", a)
	}
}

func TestInternetLockFreezesWhenOnAndCanBeWidened(t *testing.T) {
	frozen, _ := fakeResponse(t)
	s := lockService(t)
	_ = s.SetDryRun(false)
	_ = s.SetAutoContain(true)
	reach(s, 10, "api.anthropic.com", [4]byte{160, 79, 104, 10})
	_ = s.LockDests(`C:\x\claude.exe`)
	reach(s, 11, "files.example.org", [4]byte{198, 51, 100, 4})
	a := lockAlerts(s)
	if len(a) != 1 || a[0].Severity != engine.SevCritical || a[0].Actions[0] != "resumeall" || !frozen[10] || !frozen[11] || !frozen[12] || frozen[50] {
		t.Fatalf("alerts %+v frozen %v", a, frozen)
	}
	if err := s.ResumeAll(10); err != nil || len(frozen) != 0 {
		t.Fatalf("resume: %v %v", err, frozen)
	}
	if err := s.AllowDest(`C:\x\claude.exe`, "example.org"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.sn.destHit = map[string]time.Time{}
	s.mu.Unlock()
	reach(s, 11, "files.example.org", [4]byte{198, 51, 100, 4})
	if len(lockAlerts(s)) != 1 || len(frozen) != 0 {
		t.Fatal("an added place still freezes")
	}
	if err := s.UnlockDests(`C:\x\claude.exe`); err != nil {
		t.Fatal(err)
	}
	reach(s, 11, "else.example", [4]byte{192, 0, 2, 1})
	if len(lockAlerts(s)) != 1 || len(frozen) != 0 {
		t.Fatal("unlocked app checked")
	}
	if err := s.AllowDest(`C:\x\claude.exe`, "x.example"); err == nil {
		t.Fatal("added to the list of an unlocked app")
	}
}
