package traffic

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCategorize(t *testing.T) {
	cases := map[string]string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`:                 CatBrowser,
		`C:\Program Files (x86)\Steam\steam.exe`:                                CatGame,
		`D:\SteamLibrary\steamapps\common\Project Zomboid\ProjectZomboid64.exe`: CatGame,
		`C:\Users\j\AppData\Local\Discord\app-1.0\Discord.exe`:                  CatChat,
		`C:\Windows\System32\svchost.exe`:                                       CatSystem,
		`C:\Windows\SystemApps\Something\thing.exe`:                             CatSystem,
		`C:\Users\j\AppData\Local\AnthropicClaude\app-1\claude.exe`:             CatAI,
		`C:\Tools\mystery.exe`:                                                  CatOther,
	}
	for img, want := range cases {
		if got := Categorize(img); got != want {
			t.Errorf("%s: got %s want %s", img, got, want)
		}
	}
}

func TestOrgAndDomain(t *testing.T) {
	cases := map[string][2]string{
		"api.steampowered.com":       {"Valve (Steam)", "steampowered.com"},
		"e1234.dscx.akamaiedge.net.": {"Akamai", "akamaiedge.net"},
		"news.bbc.co.uk":             {"bbc.co.uk", "bbc.co.uk"},
		"weird-host.example.org":     {"example.org", "example.org"},
		"":                           {"Unnamed address", ""},
	}
	for h, want := range cases {
		o, d := Org(h)
		if o != want[0] || d != want[1] {
			t.Errorf("%q: got (%s,%s) want %v", h, o, d, want)
		}
	}
}

func TestBuildMothershipsAndGrouping(t *testing.T) {
	steam := `C:\Steam\steam.exe`
	game := `D:\SteamLibrary\steamapps\common\Zomboid\zomboid.exe`
	chrome := `C:\Chrome\chrome.exe`
	procs := []Proc{
		{PID: 100, PPID: 1, Image: steam},
		{PID: 200, PPID: 100, Image: game},   // launched by Steam
		{PID: 300, PPID: 1, Image: chrome},   // browser main
		{PID: 301, PPID: 300, Image: chrome}, // browser child: same program, folds in
	}
	conns := []Conn{
		{PID: 100, IP: "1.1.1.1", Host: "api.steampowered.com"},
		{PID: 100, IP: "1.1.1.2", Host: "cdn.steamcontent.com"},
		{PID: 200, IP: "2.2.2.2", Host: "game.example.com"},
		{PID: 300, IP: "3.3.3.3", Host: "www.google.com"},
		{PID: 301, IP: "3.3.3.4", Host: "fonts.gstatic.com"},
		{PID: 301, IP: "4.4.4.4"}, // unnamed
		{PID: 999, IP: "5.5.5.5"}, // unknown process: dropped
	}
	apps := Build(conns, procs, nil)
	by := map[string]App{}
	for _, a := range apps {
		by[a.Label] = a
	}
	if len(apps) != 3 {
		t.Fatalf("want 3 apps, got %d: %+v", len(apps), apps)
	}
	if by["zomboid.exe"].Mothership != `c:\steam\steam.exe` {
		t.Errorf("game should orbit Steam: %+v", by["zomboid.exe"])
	}
	if by["zomboid.exe"].Category != CatGame {
		t.Error("game category")
	}
	s := by["steam.exe"]
	if len(s.Links) != 1 || s.Links[0].Org != "Valve (Steam)" || s.Links[0].Count != 2 {
		t.Errorf("Steam's two Valve hosts should be one link: %+v", s.Links)
	}
	c := by["chrome.exe"]
	if c.Mothership != "" || len(c.PIDs) != 2 || c.Conns != 3 {
		t.Errorf("chrome processes should fold into one app with no mothership: %+v", c)
	}
	var unnamed bool
	for _, l := range c.Links {
		if l.Org == "Unnamed address" && l.Hosts[0] == "4.4.4.4" {
			unnamed = true
		}
	}
	if !unnamed {
		t.Errorf("unnamed address should show its IP: %+v", c.Links)
	}
}

func TestBuildAILinkOverridesCategory(t *testing.T) {
	img := `C:\x\helper.exe`
	apps := Build([]Conn{{PID: 5, IP: "9.9.9.9", AI: "OpenRouter"}}, []Proc{{PID: 5, PPID: 1, Image: img}}, nil)
	if apps[0].Category != CatAI || !apps[0].Links[0].AI || apps[0].Links[0].Org != "OpenRouter" {
		t.Fatalf("%+v", apps[0])
	}
}

func TestSeenLearningThenNovel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.json")
	s, err := OpenSeen(path, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if s.Novel("a", "Google", now) {
		t.Fatal("nothing is new while learning")
	}
	later := now.Add(2 * time.Hour)
	if s.Novel("a", "Google", later) {
		t.Fatal("pair seen during learning is baseline")
	}
	if !s.Novel("a", "Strange Org", later) {
		t.Fatal("first contact after learning should be new")
	}
	if s.Novel("a", "Strange Org", later.Add(25*time.Hour)) {
		t.Fatal("glow must expire")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2, _ := OpenSeen(path, time.Hour, 24*time.Hour)
	if s2.Novel("a", "Strange Org", later.Add(time.Minute)) != true {
		t.Fatal("history must persist across restarts")
	}
}

func TestMothershipIgnoresRecycledParentPID(t *testing.T) {
	t0 := time.Now()
	procs := []Proc{
		{PID: 50, PPID: 1, Image: `C:\x\unrelated.exe`, Created: t0.Add(time.Hour)}, // took PID 50 later
		{PID: 60, PPID: 50, Image: `C:\x\game.exe`, Created: t0},                    // real parent exited
	}
	conns := []Conn{{PID: 50, IP: "1.1.1.1"}, {PID: 60, IP: "2.2.2.2"}}
	for _, a := range Build(conns, procs, nil) {
		if a.Mothership != "" {
			t.Fatalf("recycled PID must not become a mothership: %+v", a)
		}
	}
}
