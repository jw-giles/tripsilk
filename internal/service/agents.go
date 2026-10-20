package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/engine"
	"tripsilk/internal/notify"
)

const (
	agentScanEvery   = 2 * time.Second
	startupScanEvery = 15 * time.Second
	configScanEvery  = 10 * time.Second
	noticeDedupFor   = 10 * time.Minute
	maxCmdShown      = 400
)

// agentState lives inside Service, guarded by Service.mu.
type agentState struct {
	roots      *agentguard.Roots
	spawns     *agentguard.SpawnTracker
	startup    *agentguard.StartupWatch
	configs    *agentguard.ConfigWatch
	cfgStatus  []agentguard.ConfigStatus
	agents     []AgentInfo
	unsup      bool            // agent guard unavailable on this OS
	startupBad map[string]bool // startup sources that couldn't be read
	recent     map[string]time.Time
	// table is the latest snapshot plus processes the sensor saw start
	// since, so a sensor event can find its parents between snapshots.
	table map[uint32]agentguard.Proc
}

func newAgentState() agentState {
	return agentState{
		roots:   agentguard.NewRoots(),
		spawns:  agentguard.NewSpawnTracker(),
		startup: agentguard.NewStartupWatch(),
		configs: agentguard.NewConfigWatch(),
		recent:  map[string]time.Time{},
		table:   map[uint32]agentguard.Proc{},
	}
}

// AgentInfo is one watched AI-connected program, for the dashboard.
type AgentInfo struct {
	PID         uint32 `json:"pid"`
	Image       string `json:"image"`
	Descendants int    `json:"descendants"`
}

func (s *Service) startAgentGuard(ctx context.Context) {
	go s.every(ctx, agentScanEvery, s.scanAgents)
	go s.every(ctx, startupScanEvery, s.scanStartup)
	go s.every(ctx, configScanEvery, s.scanConfigs)
}

// aiPIDs returns PIDs currently seen talking to remote AI services. Local
// model runtimes are servers, not agents, so they are excluded.
func (s *Service) aiPIDs() map[uint32]bool {
	out := map[uint32]bool{}
	for _, f := range s.tracker.Snapshot() {
		if !f.Local {
			out[f.PID] = true
		}
	}
	return out
}

func (s *Service) scanAgents() {
	s.agentScanMu.Lock()
	defer s.agentScanMu.Unlock()
	procs, err := agentguard.SnapshotProcs()
	if err != nil {
		s.mu.Lock()
		s.ag.unsup = errors.Is(err, engine.ErrUnsupported)
		s.mu.Unlock()
		return
	}
	s.mu.Lock()
	s.ag.roots.Mark(procs, s.aiPIDs())
	live := s.ag.roots.Live(procs)
	spawns := s.ag.spawns.Observe(procs, live)
	marked := s.ag.roots.MarkedAt()
	s.ag.table = mergeTable(s.ag.table, procs, time.Now())
	s.storeProcView(s.ag.table)
	lin := agentguard.Lineage(procs, live)
	var agents []AgentInfo
	for _, r := range s.ag.roots.List() {
		n := 0
		for _, root := range lin {
			if root == r.PID {
				n++
			}
		}
		agents = append(agents, AgentInfo{PID: r.PID, Image: r.Image, Descendants: n})
	}
	s.ag.agents = agents
	s.mu.Unlock()

	for _, sp := range spawns {
		s.reportSpawn(sp, marked)
	}
}

// reportSpawn alerts on one agent-launched program, from a snapshot or from
// the real-time sensor.
func (s *Service) reportSpawn(sp agentguard.Spawn, marked map[uint32]time.Time) {
	if strings.EqualFold(sp.Child.Image, s.selfImage) {
		return
	}
	if sp.Child.CmdLine == "" {
		agentguard.FillCmdLine(&sp.Child)
	}
	v := agentguard.Classify(sp.Child)
	if v.Level == agentguard.Ignore {
		return
	}
	if v.Level < agentguard.Severe && agentguard.Preexisting(sp, marked, 10*time.Second) {
		return
	}
	if v.Level < agentguard.Severe && s.store.IsChildAllowed(sp.Agent.Image, sp.Child.Name) {
		return
	}
	if v.Level == agentguard.Notice && s.dedup(sp) {
		return
	}
	s.Bus.Publish(spawnAlert(sp, v))
}

// mergeTable replaces the process table with a fresh snapshot, keeping
// entries from the sensor for processes started in the last few seconds
// (the snapshot may predate them).
func mergeTable(old map[uint32]agentguard.Proc, procs []agentguard.Proc, now time.Time) map[uint32]agentguard.Proc {
	t := make(map[uint32]agentguard.Proc, len(procs)+8)
	for _, p := range procs {
		t[p.PID] = p
	}
	for pid, p := range old {
		if _, ok := t[pid]; !ok && !p.Created.IsZero() && now.Sub(p.Created) < 5*time.Second {
			t[pid] = p
		}
	}
	return t
}

// dedup suppresses repeats of the same low-level spawn (same agent, program
// and command) for a while, so a coding agent opening shells doesn't flood
// the feed.
func (s *Service) dedup(sp agentguard.Spawn) bool {
	k := strings.ToLower(sp.Agent.Image + "|" + sp.Child.Name + "|" + sp.Child.CmdLine)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, t := range s.ag.recent {
		if now.Sub(t) > noticeDedupFor {
			delete(s.ag.recent, key)
		}
	}
	if t, ok := s.ag.recent[k]; ok && now.Sub(t) < noticeDedupFor {
		return true
	}
	s.ag.recent[k] = now
	return false
}

func spawnAlert(sp agentguard.Spawn, v agentguard.Verdict) engine.Alert {
	agent := filepath.Base(sp.Agent.Image)
	if sp.Agent.Image == "" {
		agent = fmt.Sprintf("PID %d", sp.Agent.PID)
	}
	cmd := sp.Child.CmdLine
	if cmd == "" {
		cmd = "(command line unavailable; the program may already have exited)"
	} else if len(cmd) > maxCmdShown {
		cmd = cmd[:maxCmdShown] + "…"
	}
	a := engine.Alert{
		Source:  "agent",
		PID:     sp.Agent.PID,
		Process: sp.Agent.Image,
		Child:   strings.ToLower(sp.Child.Name),
		Title:   agent + " started " + sp.Child.Name,
		Detail:  v.Reason + " Command: " + cmd,
	}
	switch v.Level {
	case agentguard.Severe:
		a.Severity = engine.SevCritical
		a.Title = agent + " ran a dangerous command"
		a.Detail += " If you didn't ask for this, suspend " + agent + " now and run a full scan."
		a.Actions = []string{"suspend", "block"}
		a.Summary = fmt.Sprintf("%s ran a command that %s", agent, strings.TrimPrefix(strings.TrimSuffix(v.Reason, "."), "Its command line ")+".")
		a.Why = "This is a known attack pattern. If you didn't ask your assistant to do this, it may have been tricked by something it read."
		a.Do = "suspend"
	case agentguard.Warning:
		a.Severity = engine.SevHigh
		a.Actions = []string{"allowchild", "suspend", "block"}
		a.Summary = fmt.Sprintf("%s started %s, a Windows tool assistants rarely need.", agent, sp.Child.Name)
		a.Why = "Attackers use this tool because it " + strings.TrimSuffix(strings.TrimPrefix(v.Reason, "This Windows tool "), ". AI assistants rarely need it.") + "."
		a.Do = "suspend"
	default:
		a.Severity = engine.SevLow
		a.Actions = []string{"allowchild", "suspend"}
		a.Summary = fmt.Sprintf("%s started %s.", agent, sp.Child.Name)
		a.Why = "Normal for coding assistants. Check the command under Show evidence if you didn't expect it."
		a.Do = "allowchild"
	}
	return a
}

func (s *Service) scanStartup() {
	cur, failed := agentguard.StartupEntries()
	if failed["all"] {
		return // unsupported OS
	}
	s.mu.Lock()
	added := s.ag.startup.Check(cur, failed)
	s.ag.startupBad = failed
	agents := len(s.ag.agents)
	s.mu.Unlock()
	for _, e := range added {
		if e.Where == "Scheduled task" && (strings.EqualFold(e.Name, `\`+notify.TaskName) ||
			strings.EqualFold(e.Name, `\`+notify.LegacyTaskName)) {
			continue // Tripsilk's own sign-in task
		}
		a := engine.Alert{Source: "startup", Severity: engine.SevHigh,
			Summary: "Something set " + e.Name + " to start automatically with Windows.",
			Why:     "Malware does this to keep running after a restart. If you just installed or updated something, it's probably that.",
			Title:   "New startup entry: " + e.Name,
			Detail: fmt.Sprintf("%s now runs %s. If you didn't just install or update something, check it. "+
				"You can turn it off in Task Manager > Startup apps, or in Task Scheduler for tasks.", e.Where, e.Command)}
		if e.Where == "Scheduled task" && strings.HasPrefix(strings.ToLower(e.Name), `\microsoft\`) {
			a.Severity = engine.SevLow
			a.Detail = e.Command + " was added under Microsoft's task folder, usually by Windows Update. " +
				"Malware sometimes hides there too; check it if nothing was updating."
		}
		if agents > 0 {
			a.Detail += fmt.Sprintf(" %d AI-connected program(s) were running when this appeared.", agents)
		}
		s.Bus.Publish(a)
	}
}

func (s *Service) scanConfigs() {
	status, changes := s.ag.configs.Check(agentguard.KnownConfigs())
	s.mu.Lock()
	s.ag.cfgStatus = status
	s.mu.Unlock()
	for cfg, list := range changes {
		for _, c := range list {
			verb := "added"
			if c.Before != "" {
				verb = "changed"
			}
			s.Bus.Publish(engine.Alert{Source: "agentconfig", Severity: engine.SevHigh,
				Summary: fmt.Sprintf("A new tool called %q was %s in %s.", c.Name, verb, cfg.Product),
				Why:     "Tools give an AI assistant new abilities. Instructions hidden in a web page or file can add one to keep access to your PC.",
				Title:   fmt.Sprintf("%s: AI tool %q %s", cfg.Product, c.Name, verb),
				Detail: fmt.Sprintf("%s now lets its AI run %q (%s). If you didn't set this up, remove it from %s. "+
					"Adding a tool is how injected instructions give an AI agent lasting access.",
					cfg.Product, c.Name, c.After, cfg.Path)})
		}
	}
}

// AllowChild lets an agent launch a program without low-level alerts.
// Severe command lines still alert.
func (s *Service) AllowChild(agentImage, child string) error {
	if err := s.store.AllowChild(agentImage, child); err != nil {
		return err
	}
	s.note("Allowed for this app", fmt.Sprintf("%s may start %s. Dangerous commands will still alert.", filepath.Base(agentImage), child))
	return nil
}

func (s *Service) RemoveChildAllow(agentImage, child string) error {
	if err := s.store.RemoveChildAllow(agentImage, child); err != nil {
		return err
	}
	s.note("Approval removed", fmt.Sprintf("%s starting %s will alert again.", filepath.Base(agentImage), child))
	return nil
}
