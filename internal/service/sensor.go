package service

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/channels"
	"tripsilk/internal/engine"
	"tripsilk/internal/journal"
	"tripsilk/internal/sensor"
	"tripsilk/internal/win"
)

const (
	SensorSession   = "Tripsilk Sensor"
	journalFlush    = 2 * time.Second
	nameKeep        = 30 * time.Minute // how long a DNS answer names an address
	maxNames        = 20000
	channelDedupFor = 30 * time.Minute
)

// sensorState lives inside Service, guarded by Service.mu.
type sensorState struct {
	sn        *sensor.Sensor
	j         *journal.Journal
	err       string                // why the sensor isn't running
	jErr      string                // why the journal isn't running
	names     map[netip.Addr]ipName // address -> the name a DNS lookup gave for it
	chanHit   map[string]time.Time  // image|channel -> last alert
	destHit   map[string]time.Time  // agent|place -> last off-list alert
	selfPID   uint32
	ownNet    int    // Tripsilk's own non-loopback connections and lookups seen
	ownLast   string // the last one, for the dashboard
	lastNudge time.Time
}

func newSensorState() sensorState {
	return sensorState{names: map[netip.Addr]ipName{}, chanHit: map[string]time.Time{}, destHit: map[string]time.Time{}, selfPID: uint32(os.Getpid())}
}

type ipName struct {
	name string
	pid  uint32 // the program whose lookup returned this address
	at   time.Time
}

// signed checks a program's signature before it is exempted as a
// service's own app or a browser. A variable so tests can substitute it.
var signed = win.Signed

// startSensor opens the event journal and starts real-time event tracing.
// Either can fail without stopping the rest of Tripsilk: detection falls back
// to the 2 to 5 second checks, and the coverage list says so.
func (s *Service) startSensor(ctx context.Context) {
	// The journal holds command lines, which can carry tokens or passwords
	// passed as arguments, so only Administrators and SYSTEM may read it.
	dir := filepath.Join(s.dataDir, "events")
	j, err := (*journal.Journal)(nil), win.AdminOnlyDir(dir)
	if err == nil {
		j, err = journal.Open(dir, 0, 0)
	}
	if err != nil {
		s.mu.Lock()
		s.sn.jErr = err.Error()
		s.mu.Unlock()
		s.Bus.Publish(engine.Alert{Severity: engine.SevLow, Source: "system",
			Title: "Event journal unavailable", Detail: err.Error() + ". Alerts still show here; they just aren't saved to disk."})
	} else {
		s.mu.Lock()
		s.sn.j = j
		s.mu.Unlock()
		s.Bus.Subscribe(func(a engine.Alert) { j.Write("alert", a) })
	}

	sn := sensor.New(SensorSession)
	if err := sn.Start(s.onSensor); err != nil {
		s.mu.Lock()
		s.sn.err = err.Error()
		s.mu.Unlock()
		s.Bus.Publish(engine.Alert{Severity: engine.SevLow, Source: "system",
			Title:  "Real-time sensor is off; using regular checks",
			Detail: "Windows event tracing couldn't start (" + err.Error() + "). Tripsilk is checking every 2 to 5 seconds instead, which can miss a program that starts and exits in between."})
	} else {
		s.mu.Lock()
		s.sn.sn = sn
		s.mu.Unlock()
		// The sensor sees every DNS answer on the PC, so Tripsilk stops
		// looking AI services up itself and sends nothing on the network.
		s.resolver.SetPassive(true)
	}

	go func() {
		t := time.NewTicker(journalFlush)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				if sn.Running() {
					sn.Stop()
				}
				if j != nil {
					_ = j.Close()
				}
				return
			case <-t.C:
				if j != nil {
					_ = j.Flush()
				}
				s.checkSensor()
			}
		}
	}()
}

// checkSensor notices the sensor stopping on its own (Windows ended the
// session, or another tool stopped it) and says so once.
func (s *Service) checkSensor() {
	s.mu.Lock()
	sn := s.sn.sn
	if sn == nil || sn.Running() {
		s.mu.Unlock()
		return
	}
	st := sn.Stats()
	s.sn.sn = nil
	s.resolver.SetPassive(false) // back to looking AI services up itself
	s.sn.err = st.Error
	if s.sn.err == "" {
		s.sn.err = "the tracing session was stopped from outside Tripsilk"
	}
	why := s.sn.err
	s.mu.Unlock()
	s.Bus.Publish(engine.Alert{Severity: engine.SevHigh, Source: "system",
		Summary: "Tripsilk's real-time sensor was switched off while it was running.",
		Why:     "Malware stops security tools before it acts. If you didn't restart or update anything, check this PC.",
		Do:      "fullscan",
		Title:   "Tripsilk's real-time sensor stopped",
		Detail:  "Windows event tracing stopped (" + why + "). Tripsilk is back to checking every 2 to 5 seconds. Stopping a security tool's sensor is something malware does; if you didn't restart or update anything, run a full scan, then restart Tripsilk.",
		Actions: []string{"fullscan"}})
}

func (s *Service) sensorRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sn.sn != nil && s.sn.sn.Running()
}

// onSensor handles one event, on the sensor's dispatch goroutine.
func (s *Service) onSensor(ev sensor.Event) {
	s.mu.Lock()
	j := s.sn.j
	self := s.sn.selfPID
	s.mu.Unlock()
	if j != nil && journaled(ev) {
		j.Write(string(ev.Kind), ev)
	}
	if ev.PID == self && ev.Kind != sensor.ProcStart {
		// Tripsilk's own traffic: counted, so "sends nothing" can be checked.
		if what := ownTraffic(ev); what != "" {
			s.mu.Lock()
			s.sn.ownNet++
			s.sn.ownLast = what
			s.mu.Unlock()
		}
		return
	}
	switch ev.Kind {
	case sensor.ProcStart:
		s.onProcStart(ev)
	case sensor.ProcStop:
		s.forgetProc(ev)
	case sensor.DNS:
		s.onDNS(ev)
	case sensor.Connect:
		s.onConnect(ev)
	}
}

func (s *Service) forgetProc(ev sensor.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.ag.table[ev.PID]; ok && (ev.Created.IsZero() || p.Created.IsZero() || !p.Created.After(ev.Created)) {
		delete(s.ag.table, ev.PID)
	}
}

// ownTraffic describes an event of Tripsilk's own that left the PC, or ""
// for anything local (loopback, its own process starts).
func ownTraffic(ev sensor.Event) string {
	switch ev.Kind {
	case sensor.DNS:
		return "DNS lookup of " + ev.Name
	case sensor.Connect:
		if a := ev.Remote.Addr(); a.IsValid() && !a.IsLoopback() {
			return "connection to " + ev.Remote.String()
		}
	}
	return ""
}

// journaled skips connections that never leave the PC: programs talking to
// themselves over loopback would otherwise fill the journal.
func journaled(ev sensor.Event) bool {
	if ev.Kind == sensor.Connect || ev.Kind == sensor.Accept {
		return !ev.Remote.Addr().IsLoopback()
	}
	return true
}

// onProcStart checks a new process against the agents Tripsilk tracks, the
// moment it starts. The 2-second snapshot would see it too, unless it exits
// first, so a reported spawn is marked seen to avoid a second alert.
func (s *Service) onProcStart(ev sensor.Event) {
	p := agentguard.Proc{PID: ev.PID, PPID: ev.PPID, Image: ev.Image, Created: ev.Created, CmdLine: ev.CmdLine}
	p.Name = ev.Image[strings.LastIndexAny(ev.Image, `\/`)+1:]
	agent, marked, ok := s.recordStart(p)
	if !ok || p.Name == "" {
		return
	}
	at := ev.Created
	if at.IsZero() {
		at = time.Now()
	}
	s.noteShell(agent, p, at)
	// Only shells, network tools and attack patterns count: a build run by
	// the agent starts dozens of compilers in seconds, and that's work.
	if agentguard.Classify(p).Level >= agentguard.Notice {
		s.burstSpawn(agent, at)
	}
	s.reportSpawn(agentguard.Spawn{Child: p, Agent: agent}, marked)
}

// recordStart adds a started process to the table and finds its agent.
func (s *Service) recordStart(p agentguard.Proc) (agentguard.Proc, map[uint32]time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ag.table[p.PID] = p
	agent, ok := agentguard.AgentOf(s.ag.table, p, s.ag.roots.Has)
	if !ok {
		return agentguard.Proc{}, nil, false
	}
	s.ag.spawns.MarkSeen(p)
	// A spawn alert follows; give its evidence the parent chain now rather
	// than after the next snapshot. Only for an agent's children, so an
	// ordinary process start doesn't copy the table.
	s.storeProcView(s.ag.table)
	return agent, s.ag.roots.MarkedAt(), true
}

func (s *Service) onDNS(ev sensor.Event) {
	now := time.Now()
	s.mu.Lock()
	ips := make([]net.IP, 0, len(ev.Answers))
	for _, a := range ev.Answers {
		s.sn.names[a] = ipName{name: ev.Name, pid: ev.PID, at: now}
		ips = append(ips, net.IP(a.AsSlice()))
	}
	s.resolver.Learn(ev.Name, ips)
	if len(s.sn.names) > maxNames {
		for a, n := range s.sn.names {
			if now.Sub(n.at) > nameKeep || len(s.sn.names) > maxNames {
				delete(s.sn.names, a)
			}
		}
	}
	s.mu.Unlock()
	if _, ok := channels.Match(ev.Name); ok {
		s.checkChannel(ev.PID, imagePath(ev.PID), ev.Name, "looked up")
	}
}

// onConnect names a connection from the program's own DNS lookup, which
// catches a program whose lookup event was missed or that connected again
// later. Another program's answer is trusted only for the Telegram bot API,
// whose addresses are Telegram's own: most other services share CDN
// addresses with unrelated sites, so a borrowed name could be wrong.
func (s *Service) onConnect(ev sensor.Event) {
	addr := ev.Remote.Addr()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return
	}
	// A connection to an AI service: check now rather than at the next
	// 5-second scan, so a new agent is watched before its first commands.
	if s.lookupProvider(net.IP(addr.AsSlice())) != "" {
		s.nudgeScan()
	}
	s.agentConnect(ev, addr)
	s.mu.Lock()
	n, ok := s.sn.names[addr]
	s.mu.Unlock()
	if !ok || time.Since(n.at) > nameKeep {
		return
	}
	c, ok := channels.Match(n.name)
	if ok && (n.pid == ev.PID || c.ID == "telegram-bot") {
		s.checkChannel(ev.PID, imagePath(ev.PID), n.name, "connected to")
	}
}

// nudgeScan runs the AI connection scan and agent scan now, at most once a
// second however many connections arrive.
func (s *Service) nudgeScan() {
	s.mu.Lock()
	if time.Since(s.sn.lastNudge) < time.Second {
		s.mu.Unlock()
		return
	}
	s.sn.lastNudge = time.Now()
	s.mu.Unlock()
	go func() {
		s.scanNetwork()
		s.scanAgents()
		s.nudges.Add(1)
	}()
}

// checkChannel alerts when a program with no reason to reaches a control
// channel. One alert per program and channel per half hour.
func (s *Service) checkChannel(pid uint32, image, domain, verb string) {
	c, ok := channels.Match(domain)
	if !ok || pid == 0 || pid == 4 {
		return
	}
	if image != "" && strings.EqualFold(image, s.selfImage) {
		return
	}
	if channels.Normal(c, image, signed) || (image != "" && !channels.Host(image) && s.store.IsChannelAllowed(image, c.ID)) {
		return
	}
	who := strings.ToLower(image)
	if who == "" {
		who = fmt.Sprintf("pid:%d", pid)
	}
	key := who + "|" + c.ID
	now := time.Now()
	s.mu.Lock()
	if t, seen := s.sn.chanHit[key]; seen && now.Sub(t) < channelDedupFor {
		s.mu.Unlock()
		return
	}
	s.sn.chanHit[key] = now
	for k, t := range s.sn.chanHit {
		if now.Sub(t) > channelDedupFor {
			delete(s.sn.chanHit, k)
		}
	}
	s.mu.Unlock()
	s.Bus.Publish(channelAlert(pid, image, domain, verb, c))
}

func channelAlert(pid uint32, image, domain, verb string, c channels.Channel) engine.Alert {
	name := filepath.Base(image)
	if image == "" {
		name = fmt.Sprintf("A program (PID %d, already exited)", pid)
	}
	a := engine.Alert{Source: "channel", PID: pid, Process: image, Channel: c.ID,
		Evidence: &engine.Evidence{Destination: domain},
		Summary:  fmt.Sprintf("%s %s %s (%s).", name, verb, domain, c.Name),
		Why:      channels.Why(c.Kind),
		Title:    fmt.Sprintf("%s reached %s", name, c.Name),
		Detail: fmt.Sprintf("%s %s %s, which is %s. %s "+
			"If you set this up yourself (your own bot, script or tunnel), choose Allow for this app. If not, suspend it and run a full scan.",
			name, verb, domain, c.Name, channels.Why(c.Kind))}
	switch channels.Severity(c.Kind) {
	case "high":
		a.Severity = engine.SevHigh
	case "medium":
		a.Severity = engine.SevMedium
	default:
		a.Severity = engine.SevLow
	}
	if image == "" {
		a.Actions = []string{"fullscan"}
		a.Do = "fullscan"
	} else if channels.Host(image) {
		// python.exe, powershell.exe, svchost.exe...: approving the host
		// would approve every script or service run through it.
		a.Detail = fmt.Sprintf("%s %s %s, which is %s. %s %s runs other programs and scripts, so Tripsilk can't approve it as a whole. "+
			"If you started a script that does this on purpose, you can ignore this alert. If not, suspend it and run a full scan.",
			name, verb, domain, c.Name, channels.Why(c.Kind), name)
		a.Actions = []string{"suspend", "block"}
		a.Do = "suspend"
		if c.Kind == channels.IPCheck {
			a.Actions, a.Do = nil, ""
		}
	} else if c.Kind == channels.IPCheck {
		a.Actions = []string{"allowchannel"}
	} else {
		a.Actions = []string{"allowchannel", "suspend", "block"}
		a.Do = "suspend"
	}
	return a
}

// AllowChannel lets a program reach a control channel without alerts.
func (s *Service) AllowChannel(image, channel string) error {
	if channels.Host(image) {
		return fmt.Errorf("%s runs other programs and scripts, so it can't be approved as a whole", filepath.Base(image))
	}
	if err := s.store.AllowChannel(image, channel); err != nil {
		return err
	}
	s.note("Allowed for this app", fmt.Sprintf("%s may reach %s without alerts.", filepath.Base(image), channel))
	return nil
}

// RemoveChannelAllow makes a program's contact with a channel alert again.
func (s *Service) RemoveChannelAllow(image, channel string) error {
	if err := s.store.RemoveChannelAllow(image, channel); err != nil {
		return err
	}
	s.note("Approval removed", fmt.Sprintf("%s reaching %s will alert again.", filepath.Base(image), channel))
	return nil
}

// checkTrafficChannels is the fallback while the sensor is off: names from
// the Windows DNS cache. Only the Telegram bot API is checked this way,
// because Telegram's addresses are its own; the others share CDN addresses
// with unrelated sites, and a name read back from an address could be wrong.
func (s *Service) checkTrafficChannels(conns []trafficConn) {
	for _, c := range conns {
		if ch, ok := channels.Match(c.host); ok && ch.ID == "telegram-bot" {
			s.checkChannel(c.pid, c.image, c.host, "connected to")
		}
	}
}

type trafficConn struct {
	pid   uint32
	image string
	host  string
}

// SensorInfo is the sensor and journal status for the dashboard.
type SensorInfo struct {
	sensor.Stats
	OwnTraffic   int           `json:"ownTraffic"` // Tripsilk's own network events seen by the sensor
	OwnLast      string        `json:"ownLast,omitempty"`
	Journal      journal.Stats `json:"journal"`
	JournalError string        `json:"journalError,omitempty"`
}

func (s *Service) sensorInfoLocked() SensorInfo {
	var info SensorInfo
	if s.sn.sn != nil {
		info.Stats = s.sn.sn.Stats()
	} else {
		info.Error = s.sn.err
	}
	if s.sn.j != nil {
		info.Journal = s.sn.j.Stats()
	}
	info.JournalError = s.sn.jErr
	info.OwnTraffic, info.OwnLast = s.sn.ownNet, s.sn.ownLast
	return info
}
