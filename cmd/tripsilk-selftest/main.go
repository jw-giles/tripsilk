//go:build windows

// Command tripsilk-selftest exercises every Windows-specific code path in Tripsilk
// and prints PASS / FAIL / SKIP for each. It needs only Go, not Wails:
//
//	go run ./cmd/tripsilk-selftest            (normal checks)
//	go run ./cmd/tripsilk-selftest -audit     (also tests read detection; changes
//	                                        Windows audit policy, admin only)
//
// Run it from an administrator terminal for the firewall and audit checks.
// Everything it creates (a temp folder, a firewall rule for a program path
// that doesn't exist, a child process) is removed before it exits. The
// report is also written to tripsilk-selftest.txt in the current folder.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/canary"
	"tripsilk/internal/channels"
	"tripsilk/internal/defender"
	"tripsilk/internal/engine"
	"tripsilk/internal/eventlog"
	"tripsilk/internal/sysmon"
	"tripsilk/internal/journal"
	"tripsilk/internal/netmap"
	"tripsilk/internal/notify"
	"tripsilk/internal/respond"
	"tripsilk/internal/sensor"
	"tripsilk/internal/shield"
	"tripsilk/internal/win"
)

type result struct {
	status, name, detail string
}

var results []result

func record(status, name, format string, args ...any) {
	r := result{status, name, fmt.Sprintf(format, args...)}
	results = append(results, r)
	fmt.Printf("%-4s  %-28s %s\n", r.status, r.name, r.detail)
}

func pass(name, f string, a ...any) { record("PASS", name, f, a...) }
func fail(name, f string, a ...any) { record("FAIL", name, f, a...) }
func skip(name, f string, a ...any) { record("SKIP", name, f, a...) }

func main() {
	sleeper := flag.Bool("sleeper", false, "internal: child process for the suspend test")
	audit := flag.Bool("audit", false, "also test read detection (changes audit policy)")
	_ = flag.String("marker", "", "internal: tag for the command line check")
	toast := flag.Bool("toast", false, "also show a test Windows notification")
	leak := flag.Bool("leak-session", false, "internal: start a sensor and exit without stopping it")
	rec := flag.Bool("record", false, "record raw sensor events from this test's own activity to tripsilk-etw-sample.jsonl")
	flag.Parse()
	if *sleeper {
		runSleeper()
		return
	}
	if *rec {
		recordSample()
		return
	}
	if *leak {
		if err := sensor.New(selftestSession).Start(func(sensor.Event) {}); err != nil {
			os.Exit(3)
		}
		os.Exit(0) // no Stop: the session is left behind, as after a crash
	}

	fmt.Printf("Tripsilk self-test  %s/%s  %s\n\n", runtime.GOOS, runtime.GOARCH, time.Now().Format(time.RFC1123))
	if runtime.GOOS != "windows" {
		fmt.Println("This tool tests Windows features. Run it on Windows.")
		os.Exit(2)
	}
	admin := isAdmin()
	if admin {
		pass("administrator", "running elevated")
	} else {
		skip("administrator", "not elevated: firewall and audit checks will be skipped")
	}

	testIdentity()
	testFolders()
	testProcessList()
	testTCPTable()
	testResolver()
	testAllTraffic()
	testDefender()
	testWatcher()
	testShield()
	testSuspend()
	testAgentGuard(admin)
	if admin {
		testSensor()
	} else {
		skip("real-time sensor", "needs administrator")
	}
	if admin {
		if id, err := sysmon.Latest(); err == nil {
			pass("Sysmon log", "readable; newest record %d", id)
		} else if errors.Is(err, sysmon.ErrNotInstalled) {
			skip("Sysmon log", "Sysmon isn't installed (optional)")
		} else {
			fail("Sysmon log", "%v", err)
		}
	}
	if admin {
		testEventLog()
	} else {
		skip("event log copy", "needs administrator")
	}
	if admin {
		testFirewall()
	} else {
		skip("firewall block/unblock", "needs administrator")
	}
	switch {
	case !*audit:
		skip("read detection", "run with -audit to test (changes audit policy)")
	case !admin:
		skip("read detection", "needs administrator")
	default:
		testReadAudit()
		testAuditRemoval()
	}

	if *toast {
		if err := notify.Toast("Tripsilk self-test", "If you can read this, notifications work."); err != nil {
			fail("notification", "%v", err)
		} else {
			pass("notification", "sent; check that it appeared (it shows under Windows PowerShell)")
		}
	} else {
		skip("notification", "run with -toast to show a test notification")
	}

	writeReport()
	for _, r := range results {
		if r.status == "FAIL" {
			os.Exit(1)
		}
	}
}

func testIdentity() {
	self, _ := os.Executable()
	got := win.ImagePath(uint32(os.Getpid()))
	if strings.EqualFold(filepath.Clean(got), filepath.Clean(self)) {
		pass("process path lookup", "%s", got)
	} else {
		fail("process path lookup", "got %q, want %q", got, self)
	}
}

func testProcessList() {
	m, err := netmap.ProcessNames()
	if err != nil {
		fail("process list", "%v", err)
		return
	}
	name := m[uint32(os.Getpid())]
	if name == "" {
		fail("process list", "own PID missing from %d processes", len(m))
		return
	}
	pass("process list", "%d processes, self = %s", len(m), name)
}

// testTCPTable opens loopback connections over IPv4 and IPv6 and checks the
// table attributes each to this process with the right remote port.
func testTCPTable() {
	tcpCheck("TCP table (IPv4)", "tcp4", "127.0.0.1:0")
	tcpCheck("TCP table (IPv6)", "tcp6", "[::1]:0")
}

func tcpCheck(name, network, addr string) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		if network == "tcp6" {
			skip(name, "IPv6 loopback unavailable: %v", err)
		} else {
			fail(name, "listen: %v", err)
		}
		return
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			time.Sleep(3 * time.Second)
			c.Close()
		}
	}()
	c, err := net.Dial(network, ln.Addr().String())
	if err != nil {
		fail(name, "dial: %v", err)
		return
	}
	defer c.Close()
	want := ln.Addr().String()
	conns, err := netmap.Connections()
	if err != nil {
		fail(name, "%v", err)
		return
	}
	for _, x := range conns {
		if x.PID == uint32(os.Getpid()) && x.Remote == want {
			pass(name, "%d connections; loopback test connection found with correct PID and port", len(conns))
			return
		}
	}
	fail(name, "test connection to %s (PID %d) not found among %d rows; check row layout and port byte order", want, os.Getpid(), len(conns))
}

func testResolver() {
	r := netmap.NewResolver()
	r.Refresh(0)
	n := r.ResolvedCount()
	if n > 0 {
		pass("AI provider DNS", "%d provider addresses resolved", n)
	} else {
		fail("AI provider DNS", "no provider hosts resolved; is DNS or the network down?")
	}
	// The lookups above put provider entries in the Windows DNS cache, so
	// reading the cache must find at least some of them.
	r.RefreshCache(0)
	if c := r.CachedCount(); c > 0 {
		pass("DNS cache read", "%d provider addresses found in the Windows DNS cache", c)
	} else {
		fail("DNS cache read", "no provider entries in the DNS cache right after looking them up; check that Get-DnsClientCache works in PowerShell")
	}
	if _, err := netmap.Scan(r); err != nil {
		fail("traffic map scan", "%v", err)
	} else {
		pass("traffic map scan", "completed")
	}
}

// testAllTraffic checks the all-traffic view: every connection, names from
// the DNS cache, and the listener table (with a loopback-only listener of
// our own, so no firewall prompt appears).
func testAllTraffic() {
	r := netmap.NewResolver()
	conns, err := netmap.ScanAll(r)
	if err != nil {
		fail("all traffic", "%v", err)
	} else {
		named := 0
		for _, c := range conns {
			if c.Host != "" {
				named++
			}
		}
		pass("all traffic", "%d live connections, %d named from the DNS cache (%d names known)", len(conns), named, r.HostCount())
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fail("listening ports", "listen: %v", err)
		return
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ls, err := netmap.Listeners()
	if err != nil {
		fail("listening ports", "%v", err)
		return
	}
	exposed := 0
	found := false
	for _, l := range ls {
		if l.Exposed {
			exposed++
		}
		if l.PID == uint32(os.Getpid()) && l.Port == port {
			found = true
			if l.Exposed {
				fail("listening ports", "loopback listener reported as exposed (%s)", l.Addr)
				return
			}
		}
	}
	if !found {
		fail("listening ports", "own listener on 127.0.0.1:%d not found among %d", port, len(ls))
		return
	}
	pass("listening ports", "%d listeners, %d open to the network; own loopback listener found", len(ls), exposed)
}

func testDefender() {
	st := defender.GetStatus()
	if !st.Available {
		fail("Defender status", "%s", st.Error)
	} else {
		ok, issues := st.Healthy()
		if ok {
			pass("Defender status", "healthy, definitions %s", st.SignatureVersion)
		} else {
			pass("Defender status", "readable; issues: %s", strings.Join(issues, "; "))
		}
	}
	th, err := defender.RecentThreats()
	if err != nil {
		fail("Defender detections", "%v", err)
	} else {
		pass("Defender detections", "%d recent", len(th))
	}
}

func testWatcher() {
	dir, err := os.MkdirTemp("", "tripsilk-selftest-")
	if err != nil {
		fail("tripwire watcher", "temp dir: %v", err)
		return
	}
	defer os.RemoveAll(dir)
	f := filepath.Join(dir, "bait.txt")
	if err := os.WriteFile(f, []byte("self-test bait\n"), 0o600); err != nil {
		fail("tripwire watcher", "%v", err)
		return
	}
	reg := canary.NewRegistry()
	if err := reg.Add(f); err != nil {
		fail("tripwire watcher", "%v", err)
		return
	}
	events := make(chan canary.Event, 16)
	w := canary.NewWatcher(reg, func(e canary.Event) { events <- e })
	if err := w.Sync(); err != nil {
		fail("tripwire watcher", "%v", err)
		return
	}
	defer w.Stop()
	time.Sleep(300 * time.Millisecond) // let the watch loop arm

	expect := func(name string, kind canary.EventKind, act func() error) {
		if err := act(); err != nil {
			fail(name, "action failed: %v", err)
			return
		}
		deadline := time.After(3 * time.Second)
		for {
			select {
			case e := <-events:
				if e.Kind == kind {
					pass(name, "event received")
					return
				}
			case <-deadline:
				fail(name, "no %s event within 3s", kind)
				return
			}
		}
	}
	expect("tripwire: modify", canary.Modified, func() error {
		fh, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, err = fh.WriteString("changed\n")
		fh.Close()
		return err
	})
	// How Notepad, VS Code and Word save: write a new copy, swap it in.
	expect("tripwire: save-over", canary.Replaced, func() error {
		tmp := f + ".tmp"
		if err := os.WriteFile(tmp, []byte("saved over\n"), 0o600); err != nil {
			return err
		}
		return os.Rename(tmp, f)
	})
	expect("tripwire: rename", canary.Renamed, func() error {
		return os.Rename(f, f+".moved")
	})
}

// testSuspend starts a child that prints a tick every 100ms, suspends it,
// checks the ticks stop, resumes it and checks they restart.
// testShield checks the ransomware burst detector against a real burst in a
// temp folder, the write-counter sampling, and reads Controlled Folder Access.
func testShield() {
	dir, err := os.MkdirTemp("", "tripsilk-shield-")
	if err != nil {
		fail("ransomware shield", "%v", err)
		return
	}
	defer os.RemoveAll(dir)
	got := make(chan int, 64)
	w, watched := shield.Watch([]string{dir}, func(path string) {
		if n := burst.Observe(path, time.Now()); n > 0 {
			select {
			case got <- n:
			default:
			}
		}
	})
	if len(watched) == 0 {
		fail("ransomware shield", "couldn't watch a temp folder")
		return
	}
	defer w.Stop()
	time.Sleep(300 * time.Millisecond)
	for i := 0; i < 60; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d.docx", i)), []byte("x"), 0o600)
	}
	select {
	case n := <-got:
		pass("ransomware shield", "detected a %d-file burst in a watched folder", n)
	case <-time.After(4 * time.Second):
		fail("ransomware shield", "a 60-file burst did not trigger the detector")
	}

	pids := []uint32{uint32(os.Getpid())}
	if b, _ := shield.WriteCounters(pids, true); len(b) == 0 {
		fail("write counters", "couldn't read this process's write bytes")
	} else {
		pass("write counters", "read write totals for %d process(es)", len(b))
	}

	switch cfa := defender.GetFolderProtection(); cfa {
	case defender.CFAUnknown:
		fail("folder protection", "couldn't read Controlled Folder Access")
	default:
		pass("folder protection", "Controlled Folder Access is %s", cfa)
	}
}

// burst is shared so the self-test's watcher can feed it.
var burst = shield.NewBurst(6*time.Second, 40, time.Minute)

func testSuspend() {
	self, _ := os.Executable()
	cmd := exec.Command(self, "-sleeper")
	out, err := cmd.StdoutPipe()
	if err != nil {
		fail("suspend/resume", "%v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		fail("suspend/resume", "start child: %v", err)
		return
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	ticks := make(chan struct{}, 1000)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			ticks <- struct{}{}
		}
	}()
	count := func(d time.Duration) int {
		n := 0
		end := time.After(d)
		for {
			select {
			case <-ticks:
				n++
			case <-end:
				return n
			}
		}
	}
	if count(500*time.Millisecond) == 0 {
		fail("suspend/resume", "child produced no output")
		return
	}
	pid := uint32(cmd.Process.Pid)
	image := win.ImagePath(pid)
	if err := respond.Suspend(pid, image); err != nil {
		fail("suspend/resume", "suspend: %v", err)
		return
	}
	count(200 * time.Millisecond) // drain anything buffered before the freeze
	frozen := count(800 * time.Millisecond)
	if err := respond.Resume(pid, image); err != nil {
		fail("suspend/resume", "resume: %v (child left suspended; it will be killed)", err)
		return
	}
	after := count(800 * time.Millisecond)
	switch {
	case frozen > 1:
		fail("suspend/resume", "child kept running while suspended (%d ticks)", frozen)
	case after == 0:
		fail("suspend/resume", "child did not resume")
	default:
		pass("suspend/resume", "froze (%d ticks) and resumed (%d ticks)", frozen, after)
	}

	// The guard must refuse protected processes.
	if err := respond.Suspend(4, "System"); err == nil {
		fail("protected process guard", "suspend of PID 4 was not refused")
	} else {
		pass("protected process guard", "%v", err)
	}
}

// testAgentGuard checks the process tree (parent PIDs, creation times,
// command lines) using a child this test starts, then reads startup
// entries and AI app config files.
func testAgentGuard(admin bool) {
	self, _ := os.Executable()
	cmd := exec.Command(self, "-sleeper", "-marker=tripsilk-lineage-check")
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		fail("process tree", "start child: %v", err)
		return
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	time.Sleep(300 * time.Millisecond)

	procs, err := agentguard.SnapshotProcs()
	if err != nil {
		fail("process tree", "%v", err)
		return
	}
	me, child := uint32(os.Getpid()), uint32(cmd.Process.Pid)
	var selfP, childP *agentguard.Proc
	for i := range procs {
		switch procs[i].PID {
		case me:
			selfP = &procs[i]
		case child:
			childP = &procs[i]
		}
	}
	switch {
	case selfP == nil || childP == nil:
		fail("process tree", "self or child missing from snapshot")
		return
	case childP.PPID != me:
		fail("process tree", "child parent PID = %d, want %d", childP.PPID, me)
		return
	case selfP.Created.IsZero() || childP.Created.IsZero():
		fail("process tree", "creation times unreadable")
		return
	case childP.Created.Before(selfP.Created):
		fail("process tree", "child created before parent: clock or FILETIME conversion wrong")
		return
	}
	lin := agentguard.Lineage(procs, map[uint32]bool{me: true})
	if lin[child] != me {
		fail("process tree", "child not linked to this process as its agent")
		return
	}
	pass("process tree", "%d processes; child linked with parent PID and creation times", len(procs))

	agentguard.FillCmdLine(childP)
	if strings.Contains(childP.CmdLine, "tripsilk-lineage-check") {
		pass("command line read", "%s", childP.CmdLine)
	} else {
		fail("command line read", "got %q", childP.CmdLine)
	}

	cur, failed := agentguard.StartupEntries()
	n := 0
	for _, e := range cur {
		n += len(e)
	}
	var bad []string
	for k := range failed {
		bad = append(bad, k)
	}
	switch {
	case len(bad) == 0:
		pass("startup entries", "%d entries across %d sources", n, len(cur))
	case !admin && len(bad) == 1 && failed["Scheduled task"]:
		pass("startup entries", "%d entries; scheduled tasks need administrator", n)
	default:
		fail("startup entries", "%d entries; unreadable: %s", n, strings.Join(bad, ", "))
	}

	st, _ := agentguard.NewConfigWatch().Check(agentguard.KnownConfigs())
	var found []string
	for _, c := range st {
		if c.Error != "" {
			fail("AI app tool lists", "%s: %s", c.Path, c.Error)
		} else if c.Found {
			found = append(found, fmt.Sprintf("%s (%d)", c.Product, c.Servers))
		}
	}
	if len(found) == 0 {
		skip("AI app tool lists", "no Claude/Cursor/VS Code/Windsurf MCP configs found")
	} else {
		pass("AI app tool lists", "%s", strings.Join(found, ", "))
	}
}

func runSleeper() {
	for i := 0; i < 600; i++ { // ~60s max, killed by the parent anyway
		fmt.Println(i)
		time.Sleep(100 * time.Millisecond)
	}
}

// testFirewall adds a rule for a program path that does not exist, so no
// real program is affected, then removes it.
// testEventLog writes one self-test event to the Application log and reads
// it back. The event source is removed again unless Tripsilk had it.
func testEventLog() {
	var k syscall.Handle
	kp, _ := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Services\EventLog\Application\` + eventlog.Source)
	had := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, kp, 0, syscall.KEY_READ, &k) == nil
	if had {
		syscall.RegCloseKey(k)
	}
	if err := eventlog.Register(); err != nil {
		fail("event log copy", "%v", err)
		return
	}
	if !had {
		defer eventlog.Unregister()
	}
	w, err := eventlog.Open()
	if err != nil {
		fail("event log copy", "%v", err)
		return
	}
	marker := fmt.Sprintf("tripsilk-selftest-%d", time.Now().UnixNano())
	err = w.Write(engine.Alert{Severity: engine.SevLow, Source: "system", Title: "Tripsilk self-test event", Detail: marker, Time: time.Now()})
	w.Close()
	if err != nil {
		fail("event log copy", "%v", err)
		return
	}
	out, _ := win.Run(15*time.Second, "wevtutil", "qe", "Application",
		"/q:*[System[Provider[@Name='Tripsilk'] and EventID=1010]]", "/c:5", "/rd:true", "/f:text")
	text := string(out)
	switch {
	case !strings.Contains(text, marker):
		fail("event log copy", "event written but not found by wevtutil")
	case strings.Contains(text, "cannot be found"):
		pass("event log copy", "written and read back (Event Viewer can't format it: the .NET message file is missing; the text is still in the event)")
	default:
		pass("event log copy", "written to the Application log as source Tripsilk, event ID 1010, and read back")
	}
}

func testFirewall() {
	image := `C:\Tripsilk-selftest\does-not-exist.exe`
	name, err := respond.Block(image)
	if err != nil {
		fail("firewall block", "%v", err)
		return
	}
	out, _ := win.Run(10*time.Second, "netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=out")
	if strings.Contains(strings.ToLower(string(out)), strings.ToLower(name)) {
		pass("firewall block", "rule created: %s", name)
	} else {
		fail("firewall block", "netsh succeeded but rule %q not listed", name)
	}
	if err := respond.Unblock(name); err != nil {
		fail("firewall unblock", "%v (remove manually in Windows Defender Firewall)", err)
		return
	}
	pass("firewall unblock", "rule removed")
}

func testReadAudit() {
	dir, err := os.MkdirTemp("", "tripsilk-audit-")
	if err != nil {
		fail("read detection", "%v", err)
		return
	}
	defer os.RemoveAll(dir)
	f := filepath.Join(dir, "bait.txt")
	os.WriteFile(f, []byte("audit test\n"), 0o600)
	reg := canary.NewRegistry()
	reg.Add(f)
	if err := canary.EnableReadAuditing([]string{f}); err != nil {
		fail("read detection", "enable: %v", err)
		return
	}
	start := time.Now().Add(-2 * time.Second)
	fh, err := os.Open(f)
	if err == nil {
		io.ReadAll(fh)
		fh.Close()
	}
	time.Sleep(3 * time.Second)                   // Security log write latency
	evs, err := canary.ReadEvents(reg, start, "") // "" so our own read counts
	if err != nil {
		fail("read detection", "%v", err)
		return
	}
	self, _ := os.Executable()
	for _, e := range evs {
		if strings.EqualFold(e.Process, self) {
			pass("read detection", "4663 event attributed to this process (PID %d)", e.PID)
			return
		}
	}
	fail("read detection", "%d events, none from this process; check audit policy with: auditpol /get /subcategory:\"File System\"", len(evs))
}

// testAuditRemoval checks key watch's off switch: after the audit rule is
// removed, reading the file must no longer log an event.
func testAuditRemoval() {
	dir, err := os.MkdirTemp("", "tripsilk-audit-")
	if err != nil {
		fail("audit rule removal", "%v", err)
		return
	}
	defer os.RemoveAll(dir)
	f := filepath.Join(dir, "key.txt")
	os.WriteFile(f, []byte("audit test\n"), 0o600)
	self, _ := os.Executable()
	readAndFind := func() (bool, error) {
		start := time.Now().Add(-2 * time.Second)
		if b, err := os.ReadFile(f); err != nil || len(b) == 0 {
			return false, fmt.Errorf("read test file: %v", err)
		}
		time.Sleep(3 * time.Second)
		acc, err := canary.AuditReads(start)
		if err != nil {
			return false, err
		}
		for _, a := range acc {
			if strings.EqualFold(a.Object, f) && strings.EqualFold(a.Process, self) {
				return true, nil
			}
		}
		return false, nil
	}
	if bad, err := canary.AddReadAudit([]string{f}); err != nil || len(bad) > 0 {
		fail("audit rule removal", "add: %v %v", err, bad)
		return
	}
	if seen, err := readAndFind(); err != nil || !seen {
		fail("audit rule removal", "no event while the rule was on (%v)", err)
		return
	}
	if bad, err := canary.RemoveReadAudit([]string{f}); err != nil || len(bad) > 0 {
		fail("audit rule removal", "remove: %v %v", err, bad)
		return
	}
	if seen, err := readAndFind(); err != nil {
		fail("audit rule removal", "%v", err)
	} else if seen {
		fail("audit rule removal", "reads are still logged after the rule was removed")
	} else {
		pass("audit rule removal", "events stop once the rule is removed")
	}
}

// testFolders checks that folder locations come from Windows: Tripsilk must not
// trust environment variables a normal program can set.
func testFolders() {
	dirs := map[string]string{"ProgramData": win.ProgramData(), "AppData": win.AppData(),
		"LocalAppData": win.LocalAppData(), "profile": win.Home(), "System32": win.SystemDir()}
	for name, d := range dirs {
		if fi, err := os.Stat(d); d == "" || err != nil || !fi.IsDir() {
			fail("Windows folders", "%s: %q not found (%v)", name, d, err)
			return
		}
	}
	for _, tool := range []string{"icacls.exe", "netsh.exe", "schtasks.exe", "auditpol.exe"} {
		if _, err := os.Stat(win.SystemTool(tool)); err != nil {
			fail("Windows folders", "%s not found in System32: %v", tool, err)
			return
		}
	}
	pass("Windows folders", "ProgramData %s, System32 %s", dirs["ProgramData"], dirs["System32"])
}

func isAdmin() bool {
	_, err := win.Run(5*time.Second, "net", "session")
	return err == nil
}

func writeReport() {
	var b strings.Builder
	fmt.Fprintf(&b, "Tripsilk self-test %s\n\n", time.Now().Format(time.RFC1123))
	p, f, s := 0, 0, 0
	for _, r := range results {
		fmt.Fprintf(&b, "%-4s  %-28s %s\n", r.status, r.name, r.detail)
		switch r.status {
		case "PASS":
			p++
		case "FAIL":
			f++
		default:
			s++
		}
	}
	summary := fmt.Sprintf("\n%d passed, %d failed, %d skipped\n", p, f, s)
	b.WriteString(summary)
	fmt.Print(summary)
	if err := os.WriteFile("tripsilk-selftest.txt", []byte(b.String()), 0o644); err == nil {
		fmt.Println("Report saved to tripsilk-selftest.txt")
	}
}

const selftestSession = "Tripsilk Selftest Sensor"

// testSensor checks real-time event tracing end to end: a child process
// starting and exiting, a loopback connection, and DNS lookups, each with
// the time from the action to Tripsilk receiving the event. It also checks
// that a session left behind by a crash is cleaned up, the control-channel
// rule, and that the journal reads its own events back.
func testSensor() {
	self, _ := os.Executable()
	me := uint32(os.Getpid())

	// A session leaked by a crashed run must not block the next start.
	leaked := exec.Command(self, "-leak-session")
	if err := leaked.Run(); err != nil {
		fail("sensor: crash cleanup", "couldn't start the leaking child: %v", err)
	}

	events := make(chan sensor.Event, 4096)
	sn := sensor.New(selftestSession)
	if err := sn.Start(func(e sensor.Event) {
		select {
		case events <- e:
		default:
		}
	}); err != nil {
		fail("real-time sensor", "%v", err)
		return
	}
	defer sn.Stop()
	if leaked.ProcessState != nil && leaked.ProcessState.Success() {
		pass("sensor: crash cleanup", "a session left behind by a killed run was replaced")
	} else {
		skip("sensor: crash cleanup", "the leaking child couldn't start its own session")
	}
	st := sn.Stats()
	pass("real-time sensor", "running; Windows filters by event ID: %v; hand-over every %d ms", st.Filtered, st.FlushMs)
	time.Sleep(500 * time.Millisecond) // let the providers arm

	var seen []sensor.Event
	wait := func(d time.Duration, match func(sensor.Event) bool) (sensor.Event, bool) {
		end := time.After(d)
		for {
			select {
			case e := <-events:
				seen = append(seen, e)
				if match(e) {
					return e, true
				}
			case <-end:
				return sensor.Event{}, false
			}
		}
	}
	ms := func(from time.Time, e sensor.Event) int64 { return e.Seen.Sub(from).Milliseconds() }

	// Process start and exit.
	cmd := exec.Command(self, "-sleeper", "-marker=tripsilk-sensor-check")
	cmd.Stdout = io.Discard
	t0 := time.Now()
	if err := cmd.Start(); err != nil {
		fail("sensor: process start", "start child: %v", err)
		return
	}
	child := uint32(cmd.Process.Pid)
	e, ok := wait(5*time.Second, func(e sensor.Event) bool { return e.Kind == sensor.ProcStart && e.PID == child })
	switch {
	case !ok:
		fail("sensor: process start", "no start event for the child (PID %d) within 5 s", child)
	case e.PPID != me:
		fail("sensor: process start", "child's parent reported as %d, want %d", e.PPID, me)
	default:
		cl := "command line read"
		if !strings.Contains(e.CmdLine, "tripsilk-sensor-check") {
			cl = fmt.Sprintf("command line NOT read (%q)", e.CmdLine)
		}
		img := "path " + e.Image
		if !strings.EqualFold(e.Image, self) {
			img = fmt.Sprintf("path %q, want %q", e.Image, self)
		}
		pass("sensor: process start", "seen in %d ms with the right parent; %s; %s", ms(t0, e), cl, img)
	}
	t1 := time.Now()
	cmd.Process.Kill()
	cmd.Wait()
	if e, ok := wait(5*time.Second, func(e sensor.Event) bool { return e.Kind == sensor.ProcStop && e.PID == child }); ok {
		pass("sensor: process exit", "seen in %d ms", ms(t1, e))
	} else {
		fail("sensor: process exit", "no exit event for PID %d within 5 s", child)
	}

	// A loopback connection.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fail("sensor: connection", "listen: %v", err)
	} else {
		port := uint16(ln.Addr().(*net.TCPAddr).Port)
		go func() {
			if c, err := ln.Accept(); err == nil {
				time.Sleep(time.Second)
				c.Close()
			}
		}()
		t2 := time.Now()
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			fail("sensor: connection", "dial: %v", err)
		} else {
			swapped := port>>8 | port<<8
			e, ok := wait(5*time.Second, func(e sensor.Event) bool {
				return e.Kind == sensor.Connect && e.PID == me && (e.Remote.Port() == port || e.Remote.Port() == swapped)
			})
			switch {
			case !ok:
				fail("sensor: connection", "no connect event for 127.0.0.1:%d within 5 s", port)
			case e.Remote.Port() != port:
				fail("sensor: connection", "port read byte-swapped (%d, want %d): fix parseTCP", e.Remote.Port(), port)
			case e.Remote.Addr().String() != "127.0.0.1":
				fail("sensor: connection", "remote address %v, want 127.0.0.1", e.Remote.Addr())
			default:
				pass("sensor: connection", "seen in %d ms with the right program and port", ms(t2, e))
			}
			c.Close()
		}
		ln.Close()
	}

	// DNS: a name nobody has looked up, so no cache can answer it.
	b := make([]byte, 6)
	rand.Read(b)
	fresh := "tripsilk-" + hex.EncodeToString(b) + ".example.com"
	t3 := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	net.DefaultResolver.LookupHost(ctx, fresh)
	cancel()
	e, ok = wait(5*time.Second, func(e sensor.Event) bool { return e.Kind == sensor.DNS && e.Name == fresh })
	switch {
	case !ok:
		fail("sensor: DNS lookup", "no event for %s within 5 s", fresh)
	case e.PID != me:
		fail("sensor: DNS lookup", "lookup attributed to PID %d (%s), not this process: control channels can then only be caught by connection", e.PID, win.ImagePath(e.PID))
	default:
		pass("sensor: DNS lookup", "seen in %d ms, attributed to this process", ms(t3, e))
	}

	// Control channel: the Telegram bot API from a program that isn't Telegram.
	t4 := time.Now()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	net.DefaultResolver.LookupHost(ctx, "api.telegram.org")
	cancel()
	e, ok = wait(5*time.Second, func(e sensor.Event) bool { return e.Kind == sensor.DNS && e.Name == "api.telegram.org" })
	ch, matched := channels.Match("api.telegram.org")
	tg := `C:\Users\x\AppData\Roaming\Telegram Desktop\Telegram.exe`
	switch {
	case !ok:
		fail("control channel", "no DNS event for api.telegram.org within 5 s (a cached answer may not log one; run again)")
	case !matched || channels.Normal(ch, self, win.Signed):
		fail("control channel", "api.telegram.org from this test program would not alert")
	case !channels.Normal(ch, tg, func(string) bool { return true }):
		fail("control channel", "Telegram itself would alert")
	default:
		pass("control channel", "Telegram bot API lookup by a non-Telegram program caught in %d ms; Telegram itself exempt", ms(t4, e))
	}

	// Silent: with the sensor running, Tripsilk's address resolver learns
	// from other programs' DNS answers and must send no lookups itself.
	for drained := false; !drained; {
		select {
		case e := <-events:
			seen = append(seen, e)
		default:
			drained = true
		}
	}
	pr := netmap.NewResolver()
	pr.SetPassive(true)
	pr.Refresh(0)
	pr.RefreshCache(0)
	if e, ok := wait(3*time.Second, func(e sensor.Event) bool { return e.Kind == sensor.DNS && e.PID == me }); ok {
		fail("silent", "passive resolver still looked up %s", e.Name)
	} else {
		pass("silent", "no DNS lookups from Tripsilk's resolver in passive mode (3 s watched)")
	}

	// Exemptions need a valid signature; checked offline.
	edge := filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`)
	switch {
	case win.Signed(self):
		fail("signature check", "this unsigned test program reported as signed")
	case func() bool { _, err := os.Stat(edge); return err != nil }():
		skip("signature check", "Microsoft Edge not found at %s to test a signed program", edge)
	case !win.Signed(edge):
		fail("signature check", "Microsoft Edge's signature not accepted: browsers would alert like unknown programs")
	default:
		pass("signature check", "Edge accepted as signed, this test program refused")
	}

	st = sn.Stats()
	if st.Dropped > 0 || st.Lost > 0 {
		fail("sensor: no events lost", "%d dropped by Tripsilk, %d lost by Windows, of %d", st.Dropped, st.Lost, st.Events)
	} else {
		pass("sensor: no events lost", "%d events, none dropped or lost", st.Events)
	}

	// Journal: write what was seen, read it back.
	dir, err := os.MkdirTemp("", "tripsilk-journal-")
	if err != nil {
		fail("event journal", "%v", err)
		return
	}
	defer os.RemoveAll(dir)
	j, err := journal.Open(dir, 0, 0)
	if err != nil {
		fail("event journal", "%v", err)
		return
	}
	from := time.Now().Add(-time.Second)
	for _, e := range seen {
		j.Write(string(e.Kind), e)
	}
	j.Close()
	recs, err := journal.ReadSince(dir, from, 0)
	if err != nil || len(recs) != len(seen) || len(seen) == 0 {
		fail("event journal", "wrote %d events, read back %d (%v)", len(seen), len(recs), err)
	} else {
		pass("event journal", "wrote and read back %d events", len(recs))
	}
}

// recordSample captures the raw bytes Windows sends for this program's own
// process start and exit, a loopback connection and two DNS lookups, so
// Tripsilk's parsers can be tested against real payloads. Events from any
// other program are dropped: nothing else on the PC ends up in the file.
func recordSample() {
	me := uint32(os.Getpid())
	var child uint32
	var mu sync.Mutex
	var raws []sensor.Raw
	var port4, port6 int
	sensor.RawHook = func(r sensor.Raw) {
		mu.Lock()
		defer mu.Unlock()
		pid := r.PID
		if len(r.Data) >= 4 && r.Provider != "dns" {
			pid = binary.LittleEndian.Uint32(r.Data)
		}
		if pid == me || (child != 0 && pid == child) {
			raws = append(raws, r)
		}
	}
	sn := sensor.New(selftestSession)
	if err := sn.Start(func(sensor.Event) {}); err != nil {
		fmt.Println("sensor:", err)
		os.Exit(1)
	}
	time.Sleep(500 * time.Millisecond)
	self, _ := os.Executable()
	cmd := exec.Command(self, "-sleeper", "-marker=tripsilk-record")
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err == nil {
		mu.Lock()
		child = uint32(cmd.Process.Pid)
		mu.Unlock()
		time.Sleep(time.Second)
		cmd.Process.Kill()
		cmd.Wait()
	}
	if ln, err := net.Listen("tcp4", "127.0.0.1:0"); err == nil {
		port4 = ln.Addr().(*net.TCPAddr).Port
		go func() {
			if c, err := ln.Accept(); err == nil {
				c.Close()
			}
		}()
		if c, err := net.Dial("tcp4", ln.Addr().String()); err == nil {
			c.Close()
		}
		ln.Close()
	}
	if ln, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		port6 = ln.Addr().(*net.TCPAddr).Port
		go func() {
			if c, err := ln.Accept(); err == nil {
				c.Close()
			}
		}()
		if c, err := net.Dial("tcp6", ln.Addr().String()); err == nil {
			c.Close()
		}
		ln.Close()
	}
	b := make([]byte, 6)
	rand.Read(b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	net.DefaultResolver.LookupHost(ctx, "tripsilk-"+hex.EncodeToString(b)+".example.com")
	net.DefaultResolver.LookupHost(ctx, "example.com")
	cancel()
	time.Sleep(2 * time.Second)
	sn.Stop()

	mu.Lock()
	defer mu.Unlock()
	var out strings.Builder
	fmt.Fprintf(&out, "{\"note\":\"Tripsilk sensor sample\",\"self\":%d,\"child\":%d,\"childMarker\":\"tripsilk-record\",\"listen4\":%d,\"listen6\":%d,\"os\":%q}\n", me, child, port4, port6, osVersion())
	for _, r := range raws {
		line, _ := json.Marshal(r)
		out.Write(line)
		out.WriteByte('\n')
	}
	if err := os.WriteFile("tripsilk-etw-sample.jsonl", []byte(out.String()), 0o644); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Recorded %d events to tripsilk-etw-sample.jsonl\n", len(raws))
}

func osVersion() string {
	out, _ := win.Run(5*time.Second, "cmd", "/c", "ver")
	return strings.TrimSpace(string(out))
}
