// Package burst flags an AI agent's process tree acting faster than a
// person at a keyboard could: starting many programs within seconds, or
// reaching many destinations it has never used before. It only counts; the
// caller decides what to say. Standard library only.
package burst

import (
	"strings"
	"sync"
	"time"
)

// Limits are the thresholds. The defaults are deliberately loose: a build
// or an npm install from an agent starts dozens of programs and reaches a
// handful of hosts, and that is normal work, not a burst.
type Limits struct {
	Spawns      int           // program starts by one agent's tree...
	SpawnWindow time.Duration // ...within this long
	Dests       int           // new destinations for one agent...
	DestWindow  time.Duration // ...within this long
	Quiet       time.Duration // after an alert, the same agent and kind stay quiet this long
}

// Default: 40 starts in 10 s is beyond what a person types; 12 never-seen
// destinations in 30 s is beyond what a person browses to by hand.
var Default = Limits{Spawns: 40, SpawnWindow: 10 * time.Second, Dests: 12, DestWindow: 30 * time.Second, Quiet: 10 * time.Minute}

// Kind of burst.
type Kind string

const (
	Spawns Kind = "spawns"
	Dests  Kind = "destinations"
)

// Hit is one detected burst.
type Hit struct {
	Agent  string // the agent program, as given
	Kind   Kind
	Count  int
	Window time.Duration
	Recent []string // the newest destinations, for the alert's evidence (Dests only)
}

type track struct {
	spawns []time.Time
	newAt  []time.Time
	newIDs []string
	known  map[string]bool // every destination this agent has used
	quiet  map[Kind]time.Time
	used   time.Time
}

// Detector keeps a short history per agent. Safe for concurrent use.
type Detector struct {
	mu     sync.Mutex
	lim    Limits
	agents map[string]*track
}

// maxAgents and maxKnown bound memory: an attacker can't grow the maps
// without limit by spraying destinations.
const (
	maxAgents = 256
	maxKnown  = 4096
)

func New(l Limits) *Detector {
	return &Detector{lim: l, agents: map[string]*track{}}
}

func (d *Detector) get(agent string, now time.Time) *track {
	k := strings.ToLower(agent)
	t := d.agents[k]
	if t == nil {
		if len(d.agents) >= maxAgents {
			var oldK string
			var oldT time.Time
			for kk, tt := range d.agents {
				if oldK == "" || tt.used.Before(oldT) {
					oldK, oldT = kk, tt.used
				}
			}
			delete(d.agents, oldK)
		}
		t = &track{known: map[string]bool{}, quiet: map[Kind]time.Time{}}
		d.agents[k] = t
	}
	t.used = now
	return t
}

func trim(ts []time.Time, from time.Time) int {
	i := 0
	for i < len(ts) && ts[i].Before(from) {
		i++
	}
	return i
}

func (d *Detector) fire(t *track, k Kind, now time.Time) bool {
	if q, ok := t.quiet[k]; ok && now.Sub(q) < d.lim.Quiet {
		return false
	}
	t.quiet[k] = now
	return true
}

// Spawn records a program start in agent's tree.
func (d *Detector) Spawn(agent string, at time.Time) (Hit, bool) {
	if agent == "" || d.lim.Spawns <= 0 {
		return Hit{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	t := d.get(agent, at)
	t.spawns = append(t.spawns, at)
	t.spawns = t.spawns[trim(t.spawns, at.Add(-d.lim.SpawnWindow)):]
	if n := len(t.spawns); n >= d.lim.Spawns && d.fire(t, Spawns, at) {
		return Hit{Agent: agent, Kind: Spawns, Count: n, Window: d.lim.SpawnWindow}, true
	}
	return Hit{}, false
}

// Dest records a connection from agent's tree. dest names the destination
// (a host name, or an address group when no name is known); only ones the
// agent hasn't used before count. The first time an agent is seen, its
// first destinations are all new, so a just-started agent needs as many
// fresh destinations as anyone else to trip the limit.
func (d *Detector) Dest(agent, dest string, at time.Time) (Hit, bool) {
	if agent == "" || dest == "" || d.lim.Dests <= 0 {
		return Hit{}, false
	}
	dest = strings.ToLower(dest)
	d.mu.Lock()
	defer d.mu.Unlock()
	t := d.get(agent, at)
	if t.known[dest] {
		return Hit{}, false
	}
	if len(t.known) >= maxKnown {
		t.known = map[string]bool{}
	}
	t.known[dest] = true
	t.newAt = append(t.newAt, at)
	t.newIDs = append(t.newIDs, dest)
	i := trim(t.newAt, at.Add(-d.lim.DestWindow))
	t.newAt, t.newIDs = t.newAt[i:], t.newIDs[i:]
	if n := len(t.newAt); n >= d.lim.Dests && d.fire(t, Dests, at) {
		recent := append([]string(nil), t.newIDs...)
		if len(recent) > 8 {
			recent = recent[len(recent)-8:]
		}
		return Hit{Agent: agent, Kind: Dests, Count: n, Window: d.lim.DestWindow, Recent: recent}, true
	}
	return Hit{}, false
}
