package service

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/engine"
)

// The internet allowlist (week 3): an agent's internet can be locked to the
// places it has used. Its programs reaching anywhere else freeze the agent
// with everything it started, through the same containment as a trip line:
// in practice mode, or with automatic freezing off, Tripsilk only records
// what it would have frozen.
//
// Windows Firewall can't limit one process tree to a list of sites, so this
// freezes rather than blocks: the connection that tripped it has already
// been made, and its first packets may have left.

// destQuiet: one alert per agent and place in this long.
const destQuiet = 10 * time.Minute

// checkDest learns where an unlocked agent goes, and acts on a locked one
// reaching somewhere off its list.
func (s *Service) checkDest(agent agentguard.Proc, pid uint32, who, dest, host string, addr netip.Addr, now time.Time) {
	if dest == "" {
		return
	}
	locked, allowed := s.store.DestAllowed(agent.Image, dest)
	if !locked {
		// Learning stops at the lock: a place reached while locked isn't
		// added to what "lock to what it uses" would approve next time.
		_, _ = s.store.NoteDest(agent.Image, dest)
		return
	}
	if allowed {
		return
	}
	key := strings.ToLower(agent.Image) + "|" + strings.ToLower(dest)
	s.mu.Lock()
	if t, ok := s.sn.destHit[key]; ok && now.Sub(t) < destQuiet {
		s.mu.Unlock()
		return
	}
	s.sn.destHit[key] = now
	if len(s.sn.destHit) > 4096 {
		for k, t := range s.sn.destHit {
			if now.Sub(t) > destQuiet {
				delete(s.sn.destHit, k)
			}
		}
	}
	s.mu.Unlock()
	r := s.contain(agent.PID, agent.Image, now)
	s.Bus.Publish(destAlert(agent, pid, dest, host, addr, r, who))
}

func destAlert(agent agentguard.Proc, pid uint32, dest, host string, addr netip.Addr, r containResult, who string) engine.Alert {
	name := winBase(agent.Image)
	where := dest
	if host != "" && !strings.EqualFold(host, dest) {
		where = fmt.Sprintf("%s (%s)", dest, host)
	}
	by := name
	if who != "" && !strings.EqualFold(who, agent.Image) {
		by = fmt.Sprintf("%s, running under %s,", winBase(who), name)
	}
	a := engine.Alert{Severity: engine.SevHigh, Source: "allowlist", PID: agent.PID, Process: agent.Image, Dest: dest,
		Title:   name + " reached a place outside its internet lock",
		Summary: fmt.Sprintf("%s reached %s, which isn't on its list.", by, where),
		Detail: fmt.Sprintf("%s connected to %s (address %s) from PID %d. %s's internet is locked to the places on its card, and this isn't one. "+
			"If you asked it to use this site, choose Add to its list.", by, where, addr, pid, name)}
	a.Detail += " " + containNote(agent.Image, r)
	if !r.practice && r.frozen > 0 {
		a.Severity = engine.SevCritical
		a.Why = "An agent going somewhere new can mean it was told to by something it read. Tripsilk froze it; resume it only if you asked for this."
		a.Actions, a.Do = []string{"resumeall", "allowdest", "terminate"}, ""
	} else {
		a.Why = "An agent going somewhere new can mean it was told to by something it read. If you didn't ask for this, suspend it."
		a.Actions, a.Do = []string{"suspend", "allowdest", "block"}, "suspend"
	}
	return a
}

// winBase is a Windows path's file name on any OS (tests run on Linux).
func winBase(p string) string { return p[strings.LastIndexAny(p, `\/`)+1:] }

// LockDests locks an agent's internet to the places it has used.
func (s *Service) LockDests(image string) error {
	if err := s.store.LockDests(image); err != nil {
		return err
	}
	n := len(s.store.Get().DestAllow[strings.ToLower(image)])
	s.note("Internet locked", fmt.Sprintf("%s may reach the %s it has used. Anything else freezes it (or, in practice, is recorded).",
		filepath.Base(image), plural(n, "place")))
	return nil
}

// UnlockDests lets an agent reach anywhere again.
func (s *Service) UnlockDests(image string) error {
	if err := s.store.UnlockDests(image); err != nil {
		return err
	}
	s.note("Internet lock removed", filepath.Base(image)+" may reach anywhere again.")
	return nil
}

// AllowDest adds a place to an agent's lock.
func (s *Service) AllowDest(image, dest string) error {
	if err := s.store.AllowDest(image, dest); err != nil {
		return err
	}
	s.note("Added to its list", fmt.Sprintf("%s may reach %s.", filepath.Base(image), dest))
	return nil
}

// RemoveDest takes a place off an agent's lock.
func (s *Service) RemoveDest(image, dest string) error {
	return s.store.RemoveDest(image, dest)
}
