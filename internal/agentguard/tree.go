// Package agentguard watches what AI-connected programs do, not just whether
// they connect. A hijacked agent is usually one the user trusts, so the
// useful signal is behavior: what it launches, what it makes start at boot,
// and what tools it gives itself.
//
// Everything here is read-only. Snapshots are polled every 2 seconds; when
// the real-time sensor (package sensor) runs, each process start is also
// checked as it happens, so short-lived programs aren't missed.
package agentguard

import (
	"strings"
	"time"
)

// Proc is one process in a snapshot.
type Proc struct {
	PID     uint32
	PPID    uint32
	Name    string    // image base name, e.g. "powershell.exe"
	Image   string    // full path when readable
	Created time.Time // zero when unreadable
	CmdLine string    // filled lazily, only for processes we report on
}

// key identifies a process instance across polls; PIDs alone get reused.
type key struct {
	pid     uint32
	created int64
}

func keyOf(p Proc) key { return key{p.PID, p.Created.UnixNano()} }

// Lineage maps each descendant PID of a root to that root's PID.
//
// A child is only linked to its parent when the parent was created no later
// than the child. Windows does not clear a dead parent's PID from its
// children, so without this check a recycled PID would make an unrelated
// process look like an agent's child.
func Lineage(procs []Proc, roots map[uint32]bool) map[uint32]uint32 {
	byPID := make(map[uint32]Proc, len(procs))
	children := make(map[uint32][]Proc)
	for _, p := range procs {
		byPID[p.PID] = p
		if p.PPID != p.PID {
			children[p.PPID] = append(children[p.PPID], p)
		}
	}
	out := map[uint32]uint32{}
	var walk func(parent Proc, root uint32, depth int)
	walk = func(parent Proc, root uint32, depth int) {
		if depth > 64 {
			return
		}
		for _, c := range children[parent.PID] {
			if _, done := out[c.PID]; done || roots[c.PID] {
				continue
			}
			if !parent.Created.IsZero() && !c.Created.IsZero() && c.Created.Before(parent.Created) {
				continue // parent PID was recycled
			}
			out[c.PID] = root
			walk(c, root, depth+1)
		}
	}
	for pid := range roots {
		if p, ok := byPID[pid]; ok {
			walk(p, pid, 0)
		}
	}
	return out
}

// Spawn is a newly seen process launched (directly or not) by an agent.
type Spawn struct {
	Child Proc
	Agent Proc
}

// SpawnTracker reports each agent-descended process once.
type SpawnTracker struct {
	seen map[key]bool
	init bool
}

func NewSpawnTracker() *SpawnTracker { return &SpawnTracker{seen: map[key]bool{}} }

// Observe returns spawns not reported before. The first call only records a
// baseline, so processes already running when Tripsilk starts don't all alert.
func (t *SpawnTracker) Observe(procs []Proc, roots map[uint32]bool) []Spawn {
	lin := Lineage(procs, roots)
	byPID := make(map[uint32]Proc, len(procs))
	live := make(map[key]bool, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
		live[keyOf(p)] = true
	}
	var out []Spawn
	for _, p := range procs {
		root, ok := lin[p.PID]
		if !ok {
			continue
		}
		k := keyOf(p)
		if t.seen[k] {
			continue
		}
		t.seen[k] = true
		if t.init {
			out = append(out, Spawn{Child: p, Agent: byPID[root]})
		}
	}
	// Forget exited processes so the map doesn't grow forever.
	for k := range t.seen {
		if !live[k] {
			delete(t.seen, k)
		}
	}
	t.init = true
	return out
}

// MarkSeen records a spawn already reported by the real-time sensor, so the
// next poll doesn't report it again.
func (t *SpawnTracker) MarkSeen(p Proc) { t.seen[keyOf(p)] = true }

// AgentOf walks a process's parents through table and returns the first
// that isRoot accepts. A parent created after its child is a recycled PID,
// not the real parent, and ends the walk.
func AgentOf(table map[uint32]Proc, child Proc, isRoot func(Proc) bool) (Proc, bool) {
	cur := child
	for depth := 0; depth < 64; depth++ {
		parent, ok := table[cur.PPID]
		if !ok || parent.PID == cur.PID || cur.PPID == 0 {
			return Proc{}, false
		}
		if !parent.Created.IsZero() && !cur.Created.IsZero() && cur.Created.Before(parent.Created) {
			return Proc{}, false
		}
		if isRoot(parent) {
			return parent, true
		}
		cur = parent
	}
	return Proc{}, false
}

// Roots tracks agent processes. A process becomes a root when it is seen
// talking to an AI service and stays one until it exits, even if it goes
// quiet, because a hijacked agent acts between API calls.
type Roots struct {
	set    map[key]Proc
	marked map[key]time.Time // when each root was first seen using AI
}

func NewRoots() *Roots { return &Roots{set: map[key]Proc{}, marked: map[key]time.Time{}} }

// Mark records AI-connected PIDs against the current snapshot.
func (r *Roots) Mark(procs []Proc, aiPIDs map[uint32]bool) {
	now := time.Now()
	for _, p := range procs {
		if p.PID > 4 && aiPIDs[p.PID] { // never treat idle/System as an agent
			k := keyOf(p)
			r.set[k] = p
			if _, ok := r.marked[k]; !ok {
				r.marked[k] = now
			}
		}
	}
}

// Live returns root PIDs still running, pruning the rest.
func (r *Roots) Live(procs []Proc) map[uint32]bool {
	live := make(map[key]bool, len(procs))
	for _, p := range procs {
		live[keyOf(p)] = true
	}
	out := map[uint32]bool{}
	for k := range r.set {
		if live[k] {
			out[k.pid] = true
		} else {
			delete(r.set, k)
			delete(r.marked, k)
		}
	}
	return out
}

// Has reports whether p is a tracked agent. Creation times from the event
// sensor and from a snapshot come from the same kernel field, but a small
// tolerance keeps a rounding difference from hiding an agent.
func (r *Roots) Has(p Proc) bool {
	for k := range r.set {
		if k.pid != p.PID {
			continue
		}
		if p.Created.IsZero() || k.created == (time.Time{}).UnixNano() {
			return true
		}
		d := p.Created.UnixNano() - k.created
		if d > -int64(50*time.Millisecond) && d < int64(50*time.Millisecond) {
			return true
		}
	}
	return false
}

// List returns the live agent processes.
func (r *Roots) List() []Proc {
	out := make([]Proc, 0, len(r.set))
	for _, p := range r.set {
		out = append(out, p)
	}
	return out
}

func lower(s string) string { return strings.ToLower(s) }

// MarkedAt returns, per live root PID, when it was first seen using AI.
func (r *Roots) MarkedAt() map[uint32]time.Time {
	out := make(map[uint32]time.Time, len(r.marked))
	for k, t := range r.marked {
		out[k.pid] = t
	}
	return out
}

// Preexisting reports whether a spawned child was already running well
// before its agent was first seen using AI (by more than margin, which covers
// Tripsilk's own detection delay). Those children are old, not new behaviour;
// callers still report them when the command itself is severe.
func Preexisting(sp Spawn, marked map[uint32]time.Time, margin time.Duration) bool {
	m, ok := marked[sp.Agent.PID]
	return ok && !sp.Child.Created.IsZero() && sp.Child.Created.Before(m.Add(-margin))
}

// Kin remembers which processes belonged to an agent's family (the agent
// itself or anything it started), for a few minutes after they exit. Audit
// events arrive in batches seconds later, often after a short-lived reader
// has already quit; Kin still knows whose it was.
type Kin struct {
	m map[uint32]kinEntry
}

type kinEntry struct {
	image   string
	agent   string
	created time.Time
	seen    time.Time
}

// kinKeep is how long an exited process stays attributable.
const kinKeep = 3 * time.Minute

func NewKin() *Kin { return &Kin{m: map[uint32]kinEntry{}} }

// Record notes the agents and their descendants in this snapshot.
func (k *Kin) Record(procs []Proc, roots map[uint32]bool, lin map[uint32]uint32, now time.Time) {
	byPID := make(map[uint32]Proc, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	note := func(p Proc, agent Proc) {
		e, ok := k.m[p.PID]
		if !ok || !strings.EqualFold(e.image, p.Image) || !e.created.Equal(p.Created) {
			e = kinEntry{image: p.Image, created: p.Created}
		}
		e.agent = agent.Image
		e.seen = now
		k.m[p.PID] = e
	}
	for pid := range roots {
		if p, ok := byPID[pid]; ok {
			note(p, p)
		}
	}
	for pid, root := range lin {
		if p, ok := byPID[pid]; ok {
			note(p, byPID[root])
		}
	}
	for pid, e := range k.m {
		if now.Sub(e.seen) > kinKeep {
			delete(k.m, pid)
		}
	}
}

// Agent returns the agent image a process belonged to when it did something
// at time `at`. The image must match, so a recycled PID isn't blamed, and the
// process must have been seen alive around then.
func (k *Kin) Agent(pid uint32, image string, at time.Time) (string, bool) {
	e, ok := k.m[pid]
	if !ok || !strings.EqualFold(e.image, image) {
		return "", false
	}
	if !e.created.IsZero() && at.Before(e.created.Add(-time.Second)) {
		return "", false // the event predates this process
	}
	if at.After(e.seen.Add(10 * time.Second)) {
		return "", false // long after it was last seen: likely a reused PID
	}
	return e.agent, e.agent != ""
}
