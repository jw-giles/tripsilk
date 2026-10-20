//go:build windows

// Command tripsilk-lab plays a harmless rogue AI agent against a running
// Tripsilk and reports what Tripsilk caught and how fast. Every action is
// benign:
//
//  1. opens a TCP connection to an AI service and sends nothing, so
//     Tripsilk treats the lab as an AI agent
//  2. starts a burst of `cmd /c echo` that each exit within milliseconds
//  3. runs PowerShell with an encoded command that only prints a word
//  4. looks up the Telegram bot API and opens a connection that sends nothing
//  5. appends a line to a lab trip-line file (only if Tripsilk watches it)
//
// It then reads Tripsilk's event journal for the alerts each action caused.
// Run from an administrator terminal while Tripsilk is running:
//
//	build\bin\tripsilk-lab.exe
//
// The report is printed and saved to tripsilk-lab.txt. -sandbox-setup
// prepares a fresh Windows Sandbox (see build\lab\README.txt).
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"tripsilk/internal/engine"
	"tripsilk/internal/journal"
	"tripsilk/internal/netmap"
	"tripsilk/internal/win"
)

const labBaitName = "tripsilk-lab-tripline.txt"

// labBait is in the user's own Documents. It used to be in Public
// Documents, which every account on the PC can change; oldLabBait is
// removed from the settings when the lab trip line is registered again.
func labBait() string {
	if d := win.Documents(); d != "" {
		return filepath.Join(d, labBaitName)
	}
	return oldLabBait()
}

func oldLabBait() string {
	pub := os.Getenv("PUBLIC")
	if pub == "" {
		pub = `C:\Users\Public`
	}
	return filepath.Join(pub, "Documents", labBaitName)
}

type step struct {
	name   string
	at     time.Time
	match  func(engine.Alert) bool
	skip   string
	caught *engine.Alert
}

// progress is appended to tripsilk-lab.log as each phase starts, and
// written to disk at once, so a run that stops or stalls still shows where.
var logFile *os.File

func progress(format string, a ...any) {
	if logFile == nil {
		return
	}
	fmt.Fprintf(logFile, "%s  %s\r\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, a...))
	logFile.Sync()
}

func main() {
	logFile, _ = os.OpenFile("tripsilk-lab.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	progress("start, pid %d, args %q", os.Getpid(), os.Args[1:])
	setup := flag.Bool("sandbox-setup", false, "prepare a fresh Windows Sandbox: create the lab trip line and Tripsilk settings with practice mode on")
	wait := flag.Duration("wait", 20*time.Second, "how long to wait for alerts after the last action")
	addLine := flag.Bool("add-tripline", false, "register the lab trip line in Tripsilk's settings (only while Tripsilk is stopped)")
	flag.Parse()

	dataDir := engine.DataDir()
	progress("data folder %s", dataDir)
	if *setup {
		sandboxSetup(dataDir)
		return
	}
	if *addLine {
		addTripline(dataDir)
		return
	}

	fmt.Printf("Tripsilk lab  %s\n\n", time.Now().Format(time.RFC1123))
	progress("header printed")
	self, _ := os.Executable()
	progress("checking that Tripsilk is running")
	if !running("tripsilk.exe") {
		progress("Tripsilk not running: exit")
		fmt.Println("Tripsilk isn't running. Start it, wait until the dashboard shows, then run the lab again.")
		os.Exit(2)
	}
	jdir := filepath.Join(dataDir, "events")
	progress("journal %s: %d files", jdir, len(journal.Files(jdir)))
	if len(journal.Files(jdir)) == 0 {
		fmt.Printf("No event journal in %s. Tripsilk 0.11 or later writes one; it needs an administrator terminal to read.\n", jdir)
		os.Exit(2)
	}
	bait := labBait()
	baitWatched := watched(dataDir, bait)
	if !baitWatched {
		if _, err := os.Stat(bait); err != nil {
			os.MkdirAll(filepath.Dir(bait), 0o755)
			os.WriteFile(bait, []byte("Tripsilk lab trip line. Nothing should touch this file except tripsilk-lab.\r\n"), 0o644)
		}
	}

	start := time.Now()
	same := func(img string) bool { return strings.EqualFold(img, self) }
	var steps []*step

	// 1. Become an agent: a TCP connection to an AI service, nothing sent.
	s1 := &step{name: "AI connection noticed", match: func(a engine.Alert) bool {
		return a.Source == "netmap" && same(a.Process)
	}}
	steps = append(steps, s1)
	s1.at = time.Now()
	progress("step 1: connecting to an AI service")
	ai, err := net.DialTimeout("tcp", "api.anthropic.com:443", 5*time.Second)
	progress("step 1: connect result %v", err)
	if err != nil {
		s1.skip = "couldn't reach api.anthropic.com: " + err.Error()
	} else {
		defer ai.Close()
		fmt.Println("Connected to an AI service (nothing sent). Waiting for Tripsilk to notice...")
		waitFor(jdir, start, s1, 15*time.Second)
		// Agent watch picks up new AI programs every 2 seconds.
		time.Sleep(3 * time.Second)
	}

	// 2. A burst of commands that each exit within milliseconds.
	s2 := &step{name: "burst of short commands", match: func(a engine.Alert) bool {
		return a.Source == "agent" && same(a.Process) && a.Child == "cmd.exe"
	}}
	steps = append(steps, s2)
	s2.at = time.Now()
	progress("step 2: short commands")
	tag := fmt.Sprintf("tripsilk-lab-%d", start.Unix()) // unique, so repeat-alert suppression doesn't hide it
	for i := 0; i < 10; i++ {
		c := exec.Command("cmd.exe", "/c", "echo", tag)
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		c.Run()
	}

	// 2b. A burst: 50 short commands as fast as they'll go, beyond what a
	// person types. The burst detector's limit is 40 in 10 seconds.
	sb := &step{name: "burst of 50 commands in seconds", match: func(a engine.Alert) bool {
		return a.Source == "burst" && same(a.Process)
	}}
	steps = append(steps, sb)
	sb.at = time.Now()
	progress("step 2b: burst")
	for i := 0; i < 50; i++ {
		c := exec.Command("cmd.exe", "/c", "exit")
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		c.Run()
	}

	// 3. An encoded PowerShell command (a classic attack pattern) that only
	// prints a word.
	s3 := &step{name: "encoded PowerShell", match: func(a engine.Alert) bool {
		return a.Source == "agent" && same(a.Process) && a.Severity == engine.SevCritical
	}}
	steps = append(steps, s3)
	s3.at = time.Now()
	progress("step 3: encoded PowerShell")
	ps := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePS("Write-Output tripsilk-lab"))
	ps.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	ps.Run()

	// 4. The Telegram bot API: a lookup and a connection that sends nothing.
	s4 := &step{name: "Telegram bot API contact", match: func(a engine.Alert) bool {
		return a.Source == "channel" && same(a.Process) && a.Channel == "telegram-bot"
	}}
	steps = append(steps, s4)
	if t, ok := recentChannelAlert(jdir, self, start); ok {
		s4.skip = fmt.Sprintf("Tripsilk alerts once per program per half hour and already did at %s; run again after %s",
			t.Local().Format("15:04"), t.Add(30*time.Minute).Local().Format("15:04"))
	}
	if s4.skip == "" { // skipped means skipped: acting would restart the repeat window
		s4.at = time.Now()
		progress("step 4: Telegram bot API")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		net.DefaultResolver.LookupHost(ctx, "api.telegram.org")
		cancel()
		if c, err := net.DialTimeout("tcp", "api.telegram.org:443", 5*time.Second); err == nil {
			c.Close()
		}
	}

	// 5. Touch the lab trip line.
	s5 := &step{name: "trip line edited", match: func(a engine.Alert) bool {
		return a.Source == "canary" && strings.Contains(strings.ToLower(a.Detail), labBaitName)
	}}
	steps = append(steps, s5)
	if !baitWatched {
		s5.skip = fmt.Sprintf("add %s as a trip line in Tripsilk (Trip lines > Add), then run the lab again", bait)
	} else {
		s5.at = time.Now()
		if f, err := os.OpenFile(bait, os.O_APPEND|os.O_WRONLY, 0); err == nil {
			f.WriteString("lab run " + time.Now().Format(time.RFC3339) + "\r\n")
			f.Close()
		} else {
			s5.skip = "couldn't edit the lab trip line: " + err.Error()
		}
	}

	// 6. Reach a place off the lab's internet lock (set by -add-tripline:
	// Anthropic and telegram.org, the lab's own steps). A TCP connection,
	// nothing sent. The site rotates every 10 minutes, since Tripsilk
	// alerts once per app and place in that time.
	s6 := &step{name: "place off its internet lock", match: func(a engine.Alert) bool {
		return a.Source == "allowlist" && same(a.Process)
	}}
	steps = append(steps, s6)
	cfg := engine.Config{}
	if st, err := engine.OpenStore(dataDir); err == nil {
		cfg = st.Get()
	}
	_, locked := cfg.DestAllow[strings.ToLower(self)]
	switch {
	case !locked:
		s6.skip = "the lab's internet isn't locked: quit Tripsilk and run tripsilk-lab -add-tripline (run-checks.bat does both)"
	case cfg.AutoContain && !cfg.DryRun:
		s6.skip = "automatic freezing is on, so this would freeze the lab itself; turn it off (or turn practice mode on) to measure this step"
	default:
		host := []string{"example.com", "example.net", "example.org"}[time.Now().Unix()/600%3]
		progress("step 6: connecting to %s", host)
		s6.at = time.Now()
		if c, err := net.DialTimeout("tcp", host+":443", 5*time.Second); err == nil {
			c.Close()
		} else {
			s6.skip = "couldn't reach " + host + ": " + err.Error()
		}
	}

	progress("actions done, waiting for alerts")
	fmt.Printf("Actions done. Waiting up to %s for alerts...\n\n", *wait)
	deadline := time.Now().Add(*wait)
	for time.Now().Before(deadline) && pending(steps) {
		collect(jdir, start, steps)
		time.Sleep(500 * time.Millisecond)
	}
	collect(jdir, start, steps)
	report(steps)
	progress("report written")
}

// recentChannelAlert finds a Telegram alert for the lab from an earlier run
// inside the half-hour repeat window.
func recentChannelAlert(jdir, self string, now time.Time) (time.Time, bool) {
	recs, _ := journal.ReadSince(jdir, now.Add(-31*time.Minute), 0)
	var last time.Time
	for _, raw := range recs {
		var r struct {
			Type string       `json:"type"`
			Data engine.Alert `json:"data"`
		}
		if json.Unmarshal(raw, &r) == nil && r.Type == "alert" && r.Data.Source == "channel" &&
			r.Data.Channel == "telegram-bot" && strings.EqualFold(r.Data.Process, self) {
			last = r.Data.Time
		}
	}
	return last, !last.IsZero() && now.Sub(last) < 30*time.Minute
}

func pending(steps []*step) bool {
	for _, s := range steps {
		if s.skip == "" && s.caught == nil {
			return true
		}
	}
	return false
}

func waitFor(jdir string, since time.Time, s *step, d time.Duration) {
	end := time.Now().Add(d)
	for time.Now().Before(end) && s.caught == nil {
		collect(jdir, since, []*step{s})
		time.Sleep(250 * time.Millisecond)
	}
}

// collect matches journaled alerts to steps. Each step takes the first
// matching alert raised after its action.
func collect(jdir string, since time.Time, steps []*step) {
	recs, _ := journal.ReadSince(jdir, since, 0)
	for _, raw := range recs {
		var r struct {
			Type string       `json:"type"`
			Data engine.Alert `json:"data"`
		}
		if json.Unmarshal(raw, &r) != nil || r.Type != "alert" {
			continue
		}
		for _, s := range steps {
			if s.caught == nil && s.skip == "" && !s.at.IsZero() && !r.Data.Time.Before(s.at) && s.match(r.Data) {
				a := r.Data
				s.caught = &a
			}
		}
	}
}

func report(steps []*step) {
	var b strings.Builder
	fmt.Fprintf(&b, "Tripsilk lab %s\n\n", time.Now().Format(time.RFC1123))
	caught, total := 0, 0
	for _, s := range steps {
		switch {
		case s.skip != "":
			fmt.Fprintf(&b, "SKIP    %-26s %s\n", s.name, s.skip)
		case s.caught != nil:
			caught++
			total++
			fmt.Fprintf(&b, "CAUGHT  %-26s %6d ms  %s\n", s.name, s.caught.Time.Sub(s.at).Milliseconds(), s.caught.Title)
		default:
			total++
			fmt.Fprintf(&b, "MISSED  %-26s no matching alert\n", s.name)
		}
	}
	if steps[0].skip == "" && steps[0].caught == nil {
		b.WriteString("\nStep 1 wasn't caught, so Tripsilk never treated the lab as an AI agent; the command steps depend on it.\n")
	}
	fmt.Fprintf(&b, "\n%d of %d caught. Times run from the action to Tripsilk raising the alert.\n", caught, total)
	b.WriteString("These alerts are from the lab, not a real attack: mark them handled in Tripsilk's Activity page.\n")
	fmt.Print(b.String())
	if err := os.WriteFile("tripsilk-lab.txt", []byte(b.String()), 0o644); err == nil {
		fmt.Println("Report saved to tripsilk-lab.txt")
	}
}

func encodePS(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func running(name string) bool {
	m, err := netmap.ProcessNames()
	if err != nil {
		return false
	}
	for _, n := range m {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// watched reports whether Tripsilk's settings list path as a trip line.
func watched(dataDir, path string) bool {
	data, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil {
		return false
	}
	var cfg engine.Config
	if json.Unmarshal(data, &cfg) != nil {
		return false
	}
	for _, p := range cfg.BaitFiles {
		if strings.EqualFold(filepath.Clean(p), filepath.Clean(path)) {
			return true
		}
	}
	return false
}

// sandboxSetup writes first-run settings for a throwaway Windows Sandbox:
// the lab trip line registered and practice mode on. It refuses to touch
// existing settings, so it can't change a real install.
func sandboxSetup(dataDir string) {
	cfgPath := filepath.Join(dataDir, "config.json")
	if _, err := os.Stat(cfgPath); err == nil {
		fmt.Printf("%s already exists; -sandbox-setup only prepares a fresh PC.\n", cfgPath)
		os.Exit(2)
	}
	bait := labBait()
	os.MkdirAll(filepath.Dir(bait), 0o755)
	if err := os.WriteFile(bait, []byte("Tripsilk lab trip line.\r\n"), 0o644); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.MkdirAll(dataDir, 0o700)
	cfg := engine.Config{BaitFiles: []string{bait}, DryRun: true}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Sandbox prepared: lab trip line registered, practice mode on.")
}

// addTripline registers the lab trip line in Tripsilk's settings. Tripsilk
// puts back any outside edit to its settings while it runs (that's how it
// resists tampering), so this only works while Tripsilk is stopped.
func addTripline(dataDir string) {
	if running("tripsilk.exe") {
		fmt.Println("Quit Tripsilk first: it undoes outside changes to its settings while running.")
		os.Exit(2)
	}
	bait := labBait()
	if _, err := os.Stat(bait); err != nil {
		os.MkdirAll(filepath.Dir(bait), 0o755)
		if err := os.WriteFile(bait, []byte("Tripsilk lab trip line. Nothing should touch this file except tripsilk-lab.\r\n"), 0o644); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
	store, err := engine.OpenStore(dataDir)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = store.Update(func(c *engine.Config) {
		kept := c.BaitFiles[:0]
		have := false
		for _, p := range c.BaitFiles {
			switch {
			case strings.EqualFold(filepath.Clean(p), filepath.Clean(oldLabBait())) && !strings.EqualFold(oldLabBait(), bait):
				continue // the old, shared location
			case strings.EqualFold(filepath.Clean(p), filepath.Clean(bait)):
				have = true
			}
			kept = append(kept, p)
		}
		c.BaitFiles = kept
		if !have {
			c.BaitFiles = append(c.BaitFiles, bait)
		}
		// Lock the lab's internet to the places its own steps use, so its
		// last step can go somewhere else and be caught.
		if self, err := os.Executable(); err == nil {
			if c.DestAllow == nil {
				c.DestAllow = map[string][]string{}
			}
			c.DestAllow[strings.ToLower(self)] = []string{"Anthropic", "telegram.org"}
		}
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Lab trip line registered:", bait)
	fmt.Println("Lab internet locked to Anthropic and telegram.org.")
}
