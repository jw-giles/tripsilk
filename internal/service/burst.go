package service

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/burst"
	"tripsilk/internal/engine"
	"tripsilk/internal/sensor"
	"tripsilk/internal/traffic"
)

// The burst detector (week 2): an AI agent's process tree starting
// programs, or reaching new destinations, faster than a person could. It
// only alerts. Freezing on a burst waits until a week of real use shows
// the limits stay quiet on normal work.

// agentOfLocked returns the agent pid belongs to: itself when it is one,
// else the nearest agent among its parents. Caller holds s.mu.
func (s *Service) agentOfLocked(pid uint32) (agentguard.Proc, bool) {
	p, ok := s.ag.table[pid]
	if !ok {
		return agentguard.Proc{}, false
	}
	if s.ag.roots.Has(p) {
		return p, true
	}
	return agentguard.AgentOf(s.ag.table, p, s.ag.roots.Has)
}

// burstSpawn counts a program start in an agent's tree.
func (s *Service) burstSpawn(agent agentguard.Proc, at time.Time) {
	if h, ok := s.burst.Spawn(agent.Image, at); ok {
		s.Bus.Publish(burstAlert(agent, h))
	}
}

// agentConnect handles a connection from an agent's tree: it counts
// toward the burst limit, teaches the agent's list of places, and is
// checked against the agent's internet lock.
func (s *Service) agentConnect(ev sensor.Event, addr netip.Addr) {
	s.mu.Lock()
	agent, ok := s.agentOfLocked(ev.PID)
	who := s.ag.table[ev.PID].Image
	n, named := s.sn.names[addr]
	s.mu.Unlock()
	if !ok || strings.EqualFold(agent.Image, s.selfImage) {
		return
	}
	host := ""
	if named && time.Since(n.at) <= nameKeep {
		host = n.name
	} else if h := s.resolver.Host(net.IP(addr.AsSlice())); h != "" {
		host = h
	}
	now := time.Now()
	// The burst count uses the host name: a site's many servers are one
	// place, but a new subdomain is new activity.
	if h, ok := s.burst.Dest(agent.Image, burstKey(host, addr), now); ok {
		s.Bus.Publish(burstAlert(agent, h))
	}
	s.checkDest(agent, ev.PID, who, place(host, addr), host, addr, now)
}

// burstKey is the host name, else the address's network.
func burstKey(host string, addr netip.Addr) string {
	if host != "" {
		return host
	}
	return network(addr)
}

// place is what an internet lock lists: the organization behind a host
// name (api.anthropic.com -> Anthropic, registry.npmjs.org -> npmjs.org),
// else the address's network, since an unnamed address has no owner
// Tripsilk can show.
func place(host string, addr netip.Addr) string {
	if host != "" {
		org, _ := traffic.Org(host)
		return org
	}
	return network(addr)
}

// network is an address's /24 (or /48 for IPv6): one CDN's many addresses
// count once, and connecting by raw address doesn't dodge the count.
func network(addr netip.Addr) string {
	addr = addr.Unmap()
	bits := 24
	if addr.Is6() {
		bits = 48
	}
	if pfx, err := addr.Prefix(bits); err == nil {
		return pfx.String()
	}
	return addr.String()
}

func burstAlert(agent agentguard.Proc, h burst.Hit) engine.Alert {
	name := filepath.Base(agent.Image)
	a := engine.Alert{Severity: engine.SevHigh, Source: "burst", PID: agent.PID, Process: agent.Image,
		Actions: []string{"suspend", "block"}, Do: "suspend"}
	secs := int(h.Window / time.Second)
	switch h.Kind {
	case burst.Spawns:
		a.Title = name + " ran commands faster than a person could"
		a.Summary = fmt.Sprintf("%s and the programs it started opened %d shells or network tools in %d seconds.", name, h.Count, secs)
		a.Why = "A hijacked agent works through commands at machine speed. If you didn't give it a big job, suspend it and look."
		a.Detail = fmt.Sprintf("%s's process tree started %d shells or network tools within %d seconds (compilers and build tools aren't counted). "+
			"A script run by an install can do this; if you didn't ask %s for one, suspend it and check the agent's activity list. "+
			"Tripsilk only alerts on bursts: it doesn't freeze anything for one.", agent.Image, h.Count, secs, name)
	case burst.Dests:
		a.Title = name + " reached many new places at once"
		a.Summary = fmt.Sprintf("%s reached %d places it had never used before, in %d seconds.", name, h.Count, secs)
		a.Why = "An agent spreading out or sending data around reaches many new places quickly. If you didn't ask it to, suspend it."
		a.Detail = fmt.Sprintf("%s's process tree reached %d destinations it hadn't used before within %d seconds. Most recent: %s. "+
			"Research or a dependency install can do this; if you didn't ask for one, suspend it and block its internet. "+
			"Tripsilk only alerts on bursts: it doesn't freeze anything for one.", agent.Image, h.Count, secs, strings.Join(h.Recent, ", "))
	}
	return a
}
