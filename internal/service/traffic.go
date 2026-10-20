package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/engine"
	"tripsilk/internal/netmap"
	"tripsilk/internal/traffic"
)

const (
	trafficScanEvery = 5 * time.Second
	seenSaveEvery    = time.Minute
	learningPeriod   = 72 * time.Hour
	newGlow          = 24 * time.Hour
)

// trafficState lives inside Service, guarded by Service.mu.
type trafficState struct {
	seen         *traffic.Seen
	apps         []traffic.App
	listeners    []netmap.Listener
	baseline     map[string]bool // exposed program|port pairs known so far
	exposedProgs map[string]bool // programs that have been exposed
	err          string
	lastSave     time.Time
	// firsts: per AI app (lowercase image), organizations it or a program
	// it launched reached for the first time after the learning period,
	// with when. The learning data for a future per-app allowlist; shown on
	// the rule cards, never alerted on.
	firsts map[string]map[string]time.Time
}

func (s *Service) startTraffic(ctx context.Context, dataDir string) {
	seen, err := traffic.OpenSeen(filepath.Join(dataDir, "seen.json"), learningPeriod, newGlow)
	if err != nil {
		s.Bus.Publish(engine.Alert{Severity: engine.SevLow, Source: "system",
			Title: "Traffic history unavailable", Detail: err.Error() + " New-connection highlighting is off."})
	}
	s.mu.Lock()
	s.tr.seen = seen
	s.mu.Unlock()
	go s.every(ctx, trafficScanEvery, s.scanTraffic)
	go func() {
		<-ctx.Done()
		if seen != nil {
			_ = seen.Save()
		}
	}()
}

func (s *Service) scanTraffic() {
	conns, err := netmap.ScanAll(s.resolver)
	if err != nil {
		s.mu.Lock()
		if errors.Is(err, engine.ErrUnsupported) {
			s.tr.err = ""
		} else {
			s.tr.err = err.Error()
		}
		s.mu.Unlock()
		return
	}
	raw, _ := agentguard.SnapshotProcs()
	procs := make([]traffic.Proc, len(raw))
	for i, p := range raw {
		procs[i] = traffic.Proc{PID: p.PID, PPID: p.PPID, Image: p.Image, Created: p.Created}
	}
	tc := make([]traffic.Conn, 0, len(conns))
	for _, c := range conns {
		tc = append(tc, traffic.Conn{PID: c.PID, IP: c.IP, Host: c.Host, AI: c.AI,
			Remote: fmt.Sprintf("%s:%d", c.IP, c.Port)})
	}

	s.mu.Lock()
	seen := s.tr.seen
	s.mu.Unlock()
	now := time.Now()
	var novel func(string, string) bool
	if seen != nil {
		novel = func(app, org string) bool { return seen.Novel(app, org, now) }
	}
	apps := traffic.Build(tc, procs, novel)
	// Tripsilk's own lookups are not the user's traffic.
	out := apps[:0]
	for _, a := range apps {
		if !strings.EqualFold(a.Image, s.selfImage) {
			out = append(out, a)
		}
	}

	if !s.sensorRunning() {
		images := make(map[uint32]string, len(raw))
		for _, p := range raw {
			images[p.PID] = p.Image
		}
		var tcs []trafficConn
		for _, c := range conns {
			if c.Host != "" {
				tcs = append(tcs, trafficConn{pid: c.PID, image: images[c.PID], host: c.Host})
			}
		}
		s.checkTrafficChannels(tcs)
	}

	listeners, lerr := netmap.Listeners()

	s.mu.Lock()
	s.recordFirstsLocked(out, now)
	s.tr.apps = out
	s.tr.err = ""
	var fresh []netmap.Listener
	if lerr == nil {
		s.tr.listeners = listeners
		fresh = s.newExposedLocked(listeners)
	}
	save := seen != nil && now.Sub(s.tr.lastSave) > seenSaveEvery
	if save {
		s.tr.lastSave = now
	}
	s.mu.Unlock()

	if save {
		_ = seen.Save()
	}
	for _, l := range fresh {
		s.Bus.Publish(listenerAlert(l))
	}
}

// firstsKeep: how long a first-time destination stays on a rule card.
const firstsKeep = 7 * 24 * time.Hour

// recordFirstsLocked notes new organizations reached by AI apps and the
// programs they launched. Caller holds s.mu.
func (s *Service) recordFirstsLocked(apps []traffic.App, now time.Time) {
	agents := map[string]bool{}
	for _, r := range s.ag.roots.List() {
		if r.Image != "" {
			agents[strings.ToLower(r.Image)] = true
		}
	}
	for _, img := range s.store.Get().AllowedProcesses {
		agents[img] = true
	}
	if s.tr.firsts == nil {
		s.tr.firsts = map[string]map[string]time.Time{}
	}
	for _, a := range apps {
		owner := ""
		switch {
		case agents[a.Key]:
			owner = a.Key
		case a.Mothership != "" && agents[a.Mothership]:
			owner = a.Mothership
		default:
			continue
		}
		for _, l := range a.Links {
			if !l.New || l.AI {
				continue // AI services are covered by service rules
			}
			m := s.tr.firsts[owner]
			if m == nil {
				m = map[string]time.Time{}
				s.tr.firsts[owner] = m
			}
			if _, ok := m[l.Org]; !ok {
				m[l.Org] = now
			}
		}
	}
	for owner, m := range s.tr.firsts {
		for org, t := range m {
			if now.Sub(t) > firstsKeep {
				delete(m, org)
			}
		}
		if len(m) == 0 {
			delete(s.tr.firsts, owner)
		}
	}
}

// FirstSeen is one first-time destination, for the rule cards.
type FirstSeen struct {
	Org  string    `json:"org"`
	Time time.Time `json:"time"`
}

// firstsLocked returns first-time destinations per AI app, newest first.
// Caller holds s.mu.
func (s *Service) firstsLocked() map[string][]FirstSeen {
	out := map[string][]FirstSeen{}
	for owner, m := range s.tr.firsts {
		for org, t := range m {
			out[owner] = append(out[owner], FirstSeen{org, t})
		}
		sort.Slice(out[owner], func(i, j int) bool { return out[owner][i].Time.After(out[owner][j].Time) })
	}
	return out
}

// listenerKey identifies an exposed program and port.
func listenerKey(l netmap.Listener) string {
	return fmt.Sprintf("%s|%d", strings.ToLower(l.Image), l.Port)
}

// dynamicPortStart is where Windows' ephemeral port range begins. Programs
// that pick a random port each launch land here.
const dynamicPortStart = 49152

// newExposedLocked returns exposed listeners not seen before. The first call
// records a baseline. Caller holds s.mu.
func (s *Service) newExposedLocked(ls []netmap.Listener) []netmap.Listener {
	first := s.tr.baseline == nil
	if first {
		s.tr.baseline = map[string]bool{}
		s.tr.exposedProgs = map[string]bool{}
	}
	var fresh []netmap.Listener
	for _, l := range ls {
		if !l.Exposed || l.Image == "" || strings.EqualFold(l.Image, s.selfImage) {
			continue
		}
		k := listenerKey(l)
		if s.tr.baseline[k] {
			continue
		}
		prog := strings.ToLower(l.Image)
		known := s.tr.exposedProgs[prog]
		s.tr.baseline[k] = true
		s.tr.exposedProgs[prog] = true
		// Alert on a new port, except a random high port from a program
		// that was already exposed (it just picked a new one this launch).
		if !first && !(known && l.Port >= dynamicPortStart) {
			fresh = append(fresh, l)
		}
	}
	return fresh
}

func listenerAlert(l netmap.Listener) engine.Alert {
	name := filepath.Base(l.Image)
	return engine.Alert{
		Source: "listener", Severity: engine.SevMedium, PID: l.PID, Process: l.Image,
		Summary: fmt.Sprintf("%s opened a door for other computers on your network to connect to it.", name),
		Why:     "Games, chat and file-sharing apps do this normally. A program you don't recognize doing it could be letting someone in.",
		Do:      "suspend",
		Title:   fmt.Sprintf("%s is accepting connections on port %d", name, l.Port),
		Detail: fmt.Sprintf("%s started listening on %s port %d, so other machines on your network may be able to connect to it. "+
			"Games, chat and file-sharing apps do this normally. If you don't recognize it, suspend it. "+
			"Windows Firewall may still be blocking it from outside.", name, l.Addr, l.Port),
		Actions: []string{"suspend"},
	}
}
