// Package service wires the detectors, the alert bus and the response actions
// together. The Wails app layer is a thin binding over this, so everything
// here is testable without a UI.
package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/burst"
	"tripsilk/internal/canary"
	"tripsilk/internal/channels"
	"tripsilk/internal/defender"
	"tripsilk/internal/engine"
	"tripsilk/internal/evidence"
	"tripsilk/internal/netmap"
	"tripsilk/internal/notify"
	"tripsilk/internal/recap"
	"tripsilk/internal/traffic"
)

const (
	netScanInterval  = 5 * time.Second
	flowExpiry       = 2 * time.Minute
	auditPollEvery   = 15 * time.Second
	defenderInterval = 5 * time.Minute
)

// Service is the running protection engine.
type Service struct {
	Bus   *engine.Bus
	store *engine.Store

	reg     *canary.Registry
	watcher *canary.Watcher

	mu        sync.Mutex
	tracker   *netmap.Tracker
	resolver  *netmap.Resolver
	netErr    string
	defStatus defender.Status
	threats   []defender.Threat
	scanning  string // "" or scan type in progress
	suspended map[uint32]string
	auditFrom time.Time
	selfImage string
	ag        agentState
	tr        trafficState
	sh        shieldState
	sn        sensorState
	contained map[uint32]containment // root PID -> what was frozen
	us        usageState
	nudges    atomic.Int64 // early scans triggered by the sensor (for tests)
	// lookupProvider names the AI service at an address ("" if none); a
	// field so tests can supply addresses.
	lookupProvider func(net.IP) string
	hasher         *evidence.Hasher
	burst          *burst.Detector
	recap          atomic.Pointer[recap.Recap]
	recapMu        sync.Mutex
	ev             evlogState
	sm             sysmonState
	sd             saidState
	procView       atomic.Pointer[map[uint32]evidence.Proc] // read-only copy for alert evidence
	// netScanMu and agentScanMu keep the early scan (nudgeScan) and the
	// periodic one from overlapping: each takes a snapshot then applies it,
	// so two at once could apply an older snapshot over a newer one.
	netScanMu, agentScanMu sync.Mutex
	dataDir                string
	signIn                 bool // sign-in task exists (cached; querying spawns schtasks)
	toasts                 *notify.Limiter
	toastErr               bool
	ackedAt                time.Time // critical alerts at or before this don't drive "danger"
	cfgFails               int       // consecutive failed settings-file checks
	installed              bool      // running from Program Files, not a dev build
	migrated               bool      // settings were copied from aWall's folder this start
	migrateErr             error     // copying them failed
}

// New opens config in dataDir and builds the service. Call Start to run it.
func New(dataDir string) (*Service, error) {
	migrated, merr := engine.MigrateLegacy(dataDir)
	store, err := engine.OpenStore(dataDir)
	if err != nil {
		return nil, err
	}
	self, _ := os.Executable()
	s := &Service{
		Bus:       engine.NewBus(500),
		store:     store,
		reg:       canary.NewRegistry(),
		tracker:   netmap.NewTracker(),
		resolver:  netmap.NewResolver(),
		suspended: map[uint32]string{},
		auditFrom: time.Now(),
		selfImage: self,
		installed: isInstalledCopy(self),
		ag:        newAgentState(),
		dataDir:   dataDir,
		toasts:    notify.NewLimiter(20 * time.Second),
		sn:        newSensorState(),
		hasher:    evidence.NewHasher(512),
		burst:     burst.New(burst.Default),
	}
	s.Bus.SetEnrich(s.enrich)
	s.lookupProvider = s.resolver.Lookup
	s.migrated, s.migrateErr = migrated, merr
	s.watcher = canary.NewWatcher(s.reg, s.onCanary)
	return s, nil
}

// Start loads bait files and launches the background loops. They stop when
// ctx is cancelled.
func (s *Service) Start(ctx context.Context) {
	cfg := s.store.Get()
	s.restoreSuspended(cfg.Suspended)
	for _, p := range cfg.BaitFiles {
		if err := s.reg.Add(p); err != nil {
			s.Bus.Publish(engine.Alert{Severity: engine.SevHigh, Source: "canary",
				Title:  "Trip line file missing",
				Detail: fmt.Sprintf("%s could not be found (%v). It may have been deleted while Tripsilk was not running.", p, err)})
		}
	}
	if err := s.watcher.Sync(); err != nil && !errors.Is(err, engine.ErrUnsupported) {
		s.Bus.Publish(engine.Alert{Severity: engine.SevMedium, Source: "system",
			Title: "Some bait folders can't be watched", Detail: err.Error()})
	}
	s.signIn = notify.StartsAtSignIn()
	s.Bus.Subscribe(s.toast)
	switch {
	case s.signIn && s.installed:
		// Point the task at this copy, and rebuild one made by an older
		// Tripsilk (whose defaults stopped it on battery and after 72 hours).
		_ = notify.SetStartAtSignIn(true, s.dataDir)
	case s.signIn:
		s.Bus.Publish(engine.Alert{Severity: engine.SevMedium, Source: "system",
			Title: "Start at sign-in points at a copy any program can change",
			Detail: "Windows starts Tripsilk as admin when you sign in, from a folder that programs without admin rights " +
				"can change. Malware could swap Tripsilk.exe for itself and be started as admin. Install Tripsilk, then turn " +
				"\"Start Tripsilk when I sign in\" off here and on again in the installed copy."})
	}
	// The sensor first: when it runs, the address resolver goes passive
	// before the first network scan, so Tripsilk never looks anything up.
	s.startSensor(ctx)
	go s.every(ctx, netScanInterval, s.scanNetwork)
	go s.every(ctx, defenderInterval, s.refreshDefender)
	go s.every(ctx, auditPollEvery, s.pollReads)
	s.startUsage(ctx)
	s.startAgentGuard(ctx)
	s.startTraffic(ctx, s.dataDir)
	s.startShield(ctx)
	s.startRecap(ctx)
	s.startEventLog()
	s.startSysmon(ctx)
	s.startSaidDid(ctx)
	s.startSettingsGuard(ctx)
	go s.every(ctx, defenderInterval, s.refreshCFA)
	go func() { <-ctx.Done(); s.watcher.Stop() }()

	switch {
	case s.migrateErr != nil:
		s.Bus.Publish(engine.Alert{Severity: engine.SevMedium, Source: "system",
			Title:  "Couldn't bring over settings from aWall",
			Detail: s.migrateErr.Error() + ". Your trip lines, approvals and rules from aWall may need setting up again."})
	case s.migrated:
		s.note("Settings brought over from aWall", "Tripsilk copied your trip lines, approvals and rules from aWall's folder. The old folder is left as it was; you can delete it.")
	}
	s.Bus.Publish(engine.Alert{Severity: engine.SevInfo, Source: "system",
		Title: "Tripsilk started", Detail: fmt.Sprintf("Watching %s.", plural(len(s.reg.List()), "trip line file"))})
}

func (s *Service) every(ctx context.Context, d time.Duration, fn func()) {
	fn()
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

// ---- Detectors ----

func (s *Service) scanNetwork() {
	s.netScanMu.Lock()
	defer s.netScanMu.Unlock()
	flows, err := netmap.Scan(s.resolver)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.netErr = err.Error()
		return
	}
	s.netErr = ""
	for _, f := range flows {
		if f.Image != "" && strings.EqualFold(f.Image, s.selfImage) {
			continue
		}
		seen, isNew := s.tracker.Observe(f)
		if !isNew {
			continue
		}
		if !seen.Local && seen.Image != "" && !s.store.RuleAllows(seen.Image, seen.Provider) {
			rule, _ := s.store.ServiceRule(seen.Image)
			s.Bus.Publish(ruleAlert(seen, rule))
			continue
		}
		if s.store.IsAllowed(seen.Image) {
			continue
		}
		s.Bus.Publish(flowAlert(seen))
	}
	s.tracker.Forget(flowExpiry)
}

func ruleAlert(f netmap.Flow, rule []string) engine.Alert {
	name := filepath.Base(f.Image)
	return engine.Alert{
		Evidence: &engine.Evidence{Destination: f.Provider + " at " + f.Remote},
		Source:   "rule", Severity: engine.SevHigh, PID: f.PID, Process: f.Image, Service: f.Provider,
		Title:   name + " broke its rule: connected to " + f.Provider,
		Summary: fmt.Sprintf("%s started using %s, which you didn't allow it to use.", name, f.Provider),
		Why:     "An assistant switching to a new AI service on its own can mean it's following someone else's instructions.",
		Do:      "suspend",
		Detail: fmt.Sprintf("You locked %s to %s. It just connected to %s (%s). "+
			"If you set this up on purpose, add %s to its rule. If not, suspend it: "+
			"an assistant suddenly using a new AI service is a sign it may be following someone else's instructions.",
			name, strings.Join(rule, ", "), f.Provider, f.Remote, f.Provider),
		Actions: []string{"addservice", "suspend", "block"},
	}
}

func flowAlert(f netmap.Flow) engine.Alert {
	name := filepath.Base(f.Image)
	if f.Image == "" {
		name = fmt.Sprintf("PID %d (path unavailable)", f.PID)
	}
	a := engine.Alert{Source: "netmap", PID: f.PID, Process: f.Image,
		Actions:  []string{"allow", "suspend", "block"},
		Evidence: &engine.Evidence{Destination: f.Provider + " at " + f.Remote}}
	if f.Local {
		a.Severity = engine.SevLow
		a.Title = "Local AI model running: " + f.Provider
		a.Summary = fmt.Sprintf("%s is running an AI model on this PC (%s).", name, f.Provider)
		a.Why = "Not a problem by itself; Tripsilk notes it so you know it's there."
		a.Do = "allow"
		a.Detail = name + " is a local model runtime. Not a threat by itself; noted so you know it's there."
		a.Actions = []string{"allow", "suspend"}
		return a
	}
	a.Severity = engine.SevMedium
	a.Title = name + " is talking to " + f.Provider
	a.Summary = fmt.Sprintf("%s is using an AI service (%s).", name, f.Provider)
	a.Why = "If you use this app with AI, that's normal. A program you don't recognize using AI could be malware asking AI what to do next."
	// No recommended button: only the user knows whether they use this app
	// with AI, and a highlighted Allow would nudge them to approve malware.
	a.Detail = fmt.Sprintf("%s connected to %s, an address that serves the %s API. "+
		"If you use this app with AI on purpose, choose Allow. If you don't recognize it, Suspend it and investigate. "+
		"Note: some AI APIs share addresses with other services, so this is a lead, not proof.", name, f.Remote, f.Provider)
	return a
}

func (s *Service) onCanary(e canary.Event) {
	a := engine.Alert{Severity: engine.SevCritical, Source: "canary", PID: e.PID, Process: e.Process}
	switch e.Kind {
	case canary.Read:
		a.Title = "Trip line opened by " + filepath.Base(e.Process)
		a.Summary = filepath.Base(e.Process) + " opened one of your trip-line files."
		a.Why = "Nothing on this PC should ever open that file, so whatever did is going through your files."
		a.Do = "suspend"
		a.Detail = fmt.Sprintf("%s read %s. Nothing on this computer should touch that file. "+
			"Suspend the process, then run a full Defender scan.", e.Process, e.Path)
		a.Actions = []string{"suspend", "block"}
		if e.PID != 0 && e.Process != "" {
			r := s.contain(e.PID, e.Process, e.When)
			a.Detail += " " + containNote(e.Process, r)
			if !r.practice && r.frozen > 0 {
				a.Actions, a.Do = []string{"resumeall", "terminate", "fullscan"}, ""
				a.Why += " Tripsilk froze it and cut its internet; resume it only if it was you."
			}
		}
	default:
		verb := string(e.Kind)
		if e.Kind == canary.Replaced {
			verb = "saved over"
		}
		a.Title = "Trip line file " + verb
		a.Summary = "One of your trip-line files was " + verb + "."
		a.Why = "Nothing on this PC should ever touch that file, so something is going through your files. Windows doesn't say which program."
		a.Do = "fullscan"
		a.Detail = fmt.Sprintf("%s was %s. Windows doesn't report which program did this; "+
			"check the AI traffic map for anything you don't recognize and run a full scan.", e.Path, verb)
		a.Actions = []string{"fullscan"}
	}
	s.Bus.Publish(a)
}

// pollReads reads the Security log for bait file reads.
func (s *Service) pollReads() {
	cfg := s.store.Get()
	if !cfg.ReadAuditing {
		return
	}
	s.mu.Lock()
	from := s.auditFrom
	s.mu.Unlock()
	now := time.Now()
	acc, err := canary.AuditReads(from)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.auditFrom = now
	s.mu.Unlock()
	for _, e := range canary.BaitReads(acc, s.reg, s.selfImage) {
		s.onCanary(e)
	}
}

func (s *Service) refreshDefender() {
	st := defender.GetStatus()
	threats, _ := defender.RecentThreats()
	s.mu.Lock()
	prev := s.defStatus
	s.defStatus = st
	s.threats = threats
	s.mu.Unlock()
	if ok, issues := st.Healthy(); !ok && st.Available {
		wasOK, _ := prev.Healthy()
		if wasOK || !prev.Available {
			s.Bus.Publish(engine.Alert{Severity: engine.SevHigh, Source: "defender",
				Title: "Microsoft Defender needs attention", Detail: strings.Join(issues, "; ") + ".",
				Summary: "Microsoft Defender isn't fully working: " + issues[0] + ".",
				Why:     "Defender catches known viruses; Tripsilk relies on it for that."})
		}
	}
}

// ---- Snapshot for the dashboard ----

type Snapshot struct {
	Overall          string                    `json:"overall"` // "protected", "attention", "danger"
	Defender         defender.Status           `json:"defender"`
	DefIssues        []string                  `json:"defenderIssues"`
	Threats          []defender.Threat         `json:"threats"`
	Flows            []netmap.Flow             `json:"flows"`
	NetError         string                    `json:"netError,omitempty"`
	Bait             []canary.Watch            `json:"bait"`
	Allowed          []string                  `json:"allowed"`
	Suspended        map[uint32]string         `json:"suspended"`
	BlockedRules     []string                  `json:"blockedRules"`
	Scanning         string                    `json:"scanning"`
	DryRun           bool                      `json:"dryRun"`
	ReadAudit        bool                      `json:"readAuditing"`
	Agents           []AgentInfo               `json:"agents"`
	AgentConfigs     []agentguard.ConfigStatus `json:"agentConfigs"`
	ChildAllow       map[string][]string       `json:"childAllow"`
	StartupCount     int                       `json:"startupCount"`
	StartupBad       []string                  `json:"startupUnreadable"`
	AgentGuard       bool                      `json:"agentGuard"`
	Toasts           bool                      `json:"toasts"`
	StartAtLogin     bool                      `json:"startAtSignIn"`
	Installed        bool                      `json:"installed"`
	ServiceRules     map[string][]string       `json:"serviceRules"`
	Violations       []Violation               `json:"violations"`
	Flagged          []string                  `json:"flagged"` // lowercase images with unacknowledged critical alerts
	Traffic          []traffic.App             `json:"traffic"`
	Listeners        []netmap.Listener         `json:"listeners"`
	TrafficError     string                    `json:"trafficError,omitempty"`
	FolderProtection string                    `json:"folderProtection"`
	ShieldOn         bool                      `json:"shieldOn"`
	Disconnected     bool                      `json:"disconnected"`
	ShieldFolders    []string                  `json:"shieldFolders"`
	Learning         bool                      `json:"learning"`
	LearningEnds     time.Time                 `json:"learningEnds"`
	Unhandled        int                       `json:"unhandled"` // high/critical alerts since the last acknowledge
	Sensor           SensorInfo                `json:"sensor"`
	SetupDone        bool                      `json:"setupDone"`
	AutoContain      bool                      `json:"autoContain"`
	Usage            Usage                     `json:"usage"`
	WouldFreeze      []engine.WouldFreeze      `json:"wouldFreeze"`
	FirstDests       map[string][]FirstSeen    `json:"firstDests"`
	ChannelAllow     map[string][]string       `json:"channelAllow"`
	DestUsed         map[string][]string       `json:"destUsed"`
	Recap            *recap.Recap              `json:"recap,omitempty"`
	EventLog         EventLogStatus            `json:"eventLog"`
	Sysmon           SysmonStatus              `json:"sysmon"`
	SaidDid          *SaidDid                  `json:"saidDid,omitempty"`
	DestAllow        map[string][]string       `json:"destAllow"`
	ChannelNames     map[string]string         `json:"channelNames"`
	Contained        []uint32                  `json:"contained"`
	Coverage         []string                  `json:"coverage"`
	NotCovered       []string                  `json:"notCovered"`
}

func (s *Service) Snapshot() Snapshot {
	cfg := s.store.Get()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, issues := s.defStatus.Healthy()
	snap := Snapshot{
		Defender: s.defStatus, DefIssues: issues, Threats: s.threats,
		Flows: s.tracker.Snapshot(), NetError: s.netErr, Bait: s.reg.List(),
		Allowed: cfg.AllowedProcesses, BlockedRules: cfg.FirewallRules,
		Scanning: s.scanning, DryRun: cfg.DryRun, ReadAudit: cfg.ReadAuditing,
		Suspended: map[uint32]string{},
		Agents:    append([]AgentInfo{}, s.ag.agents...), AgentConfigs: s.ag.cfgStatus,
		ChildAllow: cfg.AgentChildAllow, StartupCount: s.ag.startup.Count(),
		AgentGuard: !s.ag.unsup,
		Toasts:     !cfg.MuteToasts, StartAtLogin: s.signIn, Installed: s.installed,

		Traffic: s.tr.apps, Listeners: s.tr.listeners, TrafficError: s.tr.err,

		FolderProtection: string(s.sh.cfa), ShieldOn: s.sh.on,
		ShieldFolders: s.sh.folders, Disconnected: s.sh.disconnected,

		Sensor:     s.sensorInfoLocked(),
		FirstDests: s.firstsLocked(),
		SetupDone:  cfg.SetupDone, AutoContain: cfg.AutoContain, Usage: s.us.current,
		ChannelAllow: cfg.ChannelAllow, DestUsed: cfg.DestUsed, DestAllow: cfg.DestAllow, Recap: s.recapSnapshot(), EventLog: s.eventLogStatus(cfg.EventLogCopy), Sysmon: s.sysmonStatus(), SaidDid: s.saidDidSnapshot(), ChannelNames: channelNames(), WouldFreeze: cfg.WouldFreeze,
	}
	snap.Contained = []uint32{}
	for pid := range s.contained {
		snap.Contained = append(snap.Contained, pid)
	}
	if s.tr.seen != nil {
		snap.Learning, snap.LearningEnds = s.tr.seen.Learning(time.Now())
	}
	for src := range s.ag.startupBad {
		snap.StartupBad = append(snap.StartupBad, src)
	}
	for k, v := range s.suspended {
		snap.Suspended[k] = v
	}
	hist := s.Bus.History()
	snap.Overall = overall(snap, hist, s.ackedAt)
	snap.Unhandled = unhandled(hist, s.ackedAt)
	snap.Flagged = flagged(hist, s.ackedAt)
	snap.ServiceRules = cfg.ServiceRules
	snap.Violations = []Violation{}
	for _, f := range snap.Flows {
		if !f.Local && f.Image != "" && !s.store.RuleAllows(f.Image, f.Provider) {
			snap.Violations = append(snap.Violations, Violation{Image: strings.ToLower(f.Image), Service: f.Provider})
		}
	}
	snap.Coverage, snap.NotCovered = coverage(snap)
	return snap
}

func overall(snap Snapshot, recent []engine.Alert, ackedAt time.Time) string {
	cutoff := time.Now().Add(-24 * time.Hour)
	if ackedAt.After(cutoff) {
		cutoff = ackedAt
	}
	high := false
	for _, a := range recent {
		if !a.Time.After(cutoff) {
			continue
		}
		switch a.Severity {
		case engine.SevCritical:
			return "danger"
		case engine.SevHigh:
			high = true
		}
	}
	if high || len(snap.DefIssues) > 0 || len(snap.Bait) == 0 {
		return "attention"
	}
	for _, f := range snap.Flows {
		if !f.Local && !contains(snap.Allowed, strings.ToLower(f.Image)) {
			return "attention"
		}
	}
	return "protected"
}

func unhandled(recent []engine.Alert, ackedAt time.Time) int {
	cutoff := time.Now().Add(-24 * time.Hour)
	if ackedAt.After(cutoff) {
		cutoff = ackedAt
	}
	n := 0
	for _, a := range recent {
		if a.Time.After(cutoff) && (a.Severity == engine.SevHigh || a.Severity == engine.SevCritical) {
			n++
		}
	}
	return n
}

// Violation is a live connection outside an app's service rule.
type Violation struct {
	Image   string `json:"image"`
	Service string `json:"service"`
}

// flagged lists programs named in unacknowledged critical alerts, for the
// constellation view's red stars.
func flagged(recent []engine.Alert, ackedAt time.Time) []string {
	cutoff := time.Now().Add(-24 * time.Hour)
	if ackedAt.After(cutoff) {
		cutoff = ackedAt
	}
	seen := map[string]bool{}
	out := []string{}
	for _, a := range recent {
		img := strings.ToLower(a.Process)
		if a.Time.After(cutoff) && a.Severity == engine.SevCritical && img != "" && !seen[img] {
			seen[img] = true
			out = append(out, img)
		}
	}
	return out
}

// coverage lists, honestly, what is and isn't watched right now.
func coverage(snap Snapshot) (yes, no []string) {
	if ok, _ := snap.Defender.Healthy(); ok {
		yes = append(yes, "Known viruses and malware (Microsoft Defender)")
	} else {
		no = append(no, "Known malware: Defender is not fully healthy")
	}
	if snap.NetError == "" {
		yes = append(yes, "Programs connecting to AI services")
	}
	yes = append(yes, "Local AI models running on this PC")
	if len(snap.Bait) > 0 {
		yes = append(yes, "Changes to your trip line files")
	} else {
		no = append(no, "Trip lines: add at least one file")
	}
	if snap.ReadAudit {
		yes = append(yes, "Programs opening your trip line files")
	} else {
		no = append(no, "Trip line reads: turn on read detection")
	}
	if snap.Sensor.Running {
		yes = append(yes, "Every program start, the moment it happens (Windows event tracing)",
			"Programs reaching chat-bot services, paste sites, tunnels and callback catchers")
		no = append(no, "Lookups made with a program's own encrypted DNS (DNS over HTTPS) instead of Windows'")
		if snap.Sensor.OwnTraffic == 0 {
			yes = append(yes, "Tripsilk itself sends nothing on the network (checked by its own sensor)")
		} else {
			no = append(no, fmt.Sprintf("Tripsilk sent network traffic itself %d times (last: %s)", snap.Sensor.OwnTraffic, snap.Sensor.OwnLast))
		}
	} else {
		if snap.Sensor.Error != "" {
			no = append(no, "Real-time sensor: "+snap.Sensor.Error+" (checking every 2 to 5 seconds instead)",
				"Discord webhooks, paste sites and tunnels (need the real-time sensor; only the Telegram bot API is checked without it)")
		}
		no = append(no, "Tripsilk looks up AI service addresses itself every 10 minutes (DNS only), because the real-time sensor is off")
	}
	if snap.AutoContain && !snap.DryRun {
		yes = append(yes, "A program touching a trip line or acting like ransomware is frozen with everything it started")
	} else {
		no = append(no, "Automatic freezing (off: Tripsilk notes what it would freeze; turn it on in Settings)")
	}
	if snap.Sensor.Journal.Dir != "" {
		yes = append(yes, "Event journal for your own tools: "+snap.Sensor.Journal.Dir)
	}
	if snap.Sysmon.Installed {
		yes = append(yes, "Sysmon's process, network and DNS events, saved in the journal beside Tripsilk's; its launch hashes used as evidence")
		if snap.Sysmon.Error != "" {
			no = append(no, "Reading Sysmon: "+snap.Sysmon.Error)
		}
	}
	if snap.EventLog.On && snap.EventLog.Open {
		yes = append(yes, "Alerts copied to the Windows Event Log (Application, source Tripsilk)")
	} else if snap.EventLog.On {
		no = append(no, "Copying alerts to the Windows Event Log: the event source couldn't be opened")
	}
	if snap.AgentGuard {
		yes = append(yes, "Shells and system tools started by AI apps",
			"Tools (MCP servers) added to AI apps")
		if snap.Sensor.Running {
			yes = append(yes, fmt.Sprintf("An AI app opening %d shells or network tools in %d seconds, or reaching %d new places in %d seconds (alert only)",
				burst.Default.Spawns, int(burst.Default.SpawnWindow/time.Second), burst.Default.Dests, int(burst.Default.DestWindow/time.Second)))
			no = append(no, "Slower bursts: an agent working below those rates isn't flagged for speed")
			if len(snap.DestAllow) > 0 {
				yes = append(yes, "AI apps with a locked internet reaching anywhere off their list")
				no = append(no, "Internet lock: the first connection off the list is made before Tripsilk freezes the app (Windows Firewall can't limit one app's programs to a list of sites)",
					"Internet lock: places are organizations, so an approved one is approved whole (all of GitHub, all of Amazon Web Services)")
			}
		} else {
			no = append(no, "Bursts of activity by AI apps (need the real-time sensor)")
		}
		if snap.Sensor.Running {
			no = append(no, "Command lines of programs that exit within milliseconds (their name and parent are still caught)")
		} else {
			no = append(no, "Programs an AI app starts and stops within about a second")
		}
	}
	switch defender.FolderProtection(snap.FolderProtection) {
	case defender.CFAOn:
		yes = append(yes, "Ransomware blocked from your folders (Windows folder protection)")
	case defender.CFAOff:
		no = append(no, "Windows folder protection is off (turn it on under Microsoft Defender)")
	}
	if snap.ShieldOn {
		yes = append(yes, "A program suddenly rewriting many of your files (ransomware shield)")
	}
	if snap.Traffic != nil {
		yes = append(yes, "Every program's internet connections, by type",
			"Programs accepting connections from your network (TCP)")
		no = append(no, "UDP traffic (many games, calls and DNS)")
	}
	if len(snap.StartupBad) > 0 {
		no = append(no, "Some startup locations: "+strings.Join(snap.StartupBad, ", ")+" (run as administrator)")
	} else if snap.AgentGuard {
		yes = append(yes, "New programs set to run at startup")
	}
	if !snap.Installed {
		no = append(no, "Tripsilk's own program file: this copy isn't installed, so programs without admin rights could replace it")
	}
	no = append(no,
		"AI requests sent through a browser or a general cloud service",
		"Attacks that never touch your trip lines or AI services",
		"Anything with kernel-level access (rootkits)")
	return yes, no
}

// channelNames maps channel IDs to their plain names, for the rule cards.
func channelNames() map[string]string {
	m := map[string]string{}
	for _, c := range channels.All() {
		m[c.ID] = c.Name
	}
	return m
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
