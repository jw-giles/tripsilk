package service

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"tripsilk/internal/engine"
	"tripsilk/internal/respond"
)

// Containment: when a program touches a trip line or acts like ransomware,
// Tripsilk freezes it and every program it started, and blocks its internet
// access, then asks the user whether to resume or end it. Everything it
// does is reversible.
//
// It only acts for real when the user has turned on automatic containment
// and practice mode is off. Otherwise it records what it would have done,
// so the user can see a week of results before trusting it.

// containment is one frozen program family, kept so "Resume all" can undo
// exactly what was done.
type containment struct {
	root   uint32
	image  string
	frozen []frozenProc
	rule   string // firewall rule added, if any
	at     time.Time
}

type frozenProc struct {
	pid   uint32
	image string
}

// containResult describes what contain did, for the alert.
type containResult struct {
	practice bool
	frozen   int
	tree     int // programs in the family, frozen or not
	blocked  bool
	took     time.Duration
	failed   []string
}

// treeOf returns pid and all its descendants from the process table, root
// first. Caller holds s.mu.
func (s *Service) treeOfLocked(pid uint32) []frozenProc {
	out := []frozenProc{{pid: pid, image: s.ag.table[pid].Image}}
	seen := map[uint32]bool{pid: true}
	for i := 0; i < len(out) && len(out) < 256; i++ {
		parent := s.ag.table[out[i].pid]
		for _, p := range s.ag.table {
			if p.PPID != out[i].pid || seen[p.PID] {
				continue
			}
			// A "child" created before its parent holds a recycled PID.
			if !parent.Created.IsZero() && !p.Created.IsZero() && p.Created.Before(parent.Created) {
				continue
			}
			seen[p.PID] = true
			out = append(out, frozenProc{pid: p.PID, image: p.Image})
		}
	}
	return out
}

// sameProgram reports whether pid, as Tripsilk's table or Windows knows it
// now, is still the program an event at time at named. Trip-line reads
// arrive up to 15 seconds late, and Windows reuses PIDs: without this check
// containment could freeze whatever program got the number since.
// Caller holds s.mu.
func (s *Service) sameProgramLocked(pid uint32, image string, at time.Time) error {
	gone := fmt.Errorf("%s had already exited, and its process number now belongs to another program", filepath.Base(image))
	if p, ok := s.ag.table[pid]; ok && p.Image != "" {
		if !strings.EqualFold(filepath.Clean(p.Image), filepath.Clean(image)) || (!p.Created.IsZero() && p.Created.After(at)) {
			return gone
		}
		return nil
	}
	live := imagePath(pid)
	if live == "" {
		return fmt.Errorf("%s had already exited", filepath.Base(image))
	}
	if !strings.EqualFold(filepath.Clean(live), filepath.Clean(image)) {
		return gone
	}
	return nil
}

// contain freezes a program family and blocks the program's internet. at
// is when the program did what triggered it.
func (s *Service) contain(pid uint32, image string, at time.Time) containResult {
	start := time.Now()
	if at.IsZero() || at.After(start) {
		at = start
	}
	cfg := s.store.Get()
	s.mu.Lock()
	tree := s.treeOfLocked(pid)
	same := s.sameProgramLocked(pid, image, at)
	s.mu.Unlock()
	if tree[0].image == "" {
		tree[0].image = image
	}
	res := containResult{tree: len(tree), practice: cfg.DryRun || !cfg.AutoContain}
	if same != nil {
		res.failed, res.tree = []string{same.Error()}, 1
		res.took = time.Since(start)
		return res
	}
	if res.practice {
		res.took = time.Since(start)
		_ = s.store.Update(func(c *engine.Config) {
			c.WouldFreeze = append(c.WouldFreeze, engine.WouldFreeze{Time: start, Image: image, Tree: len(tree)})
			if len(c.WouldFreeze) > 50 {
				c.WouldFreeze = c.WouldFreeze[len(c.WouldFreeze)-50:]
			}
		})
		return res
	}
	// A protected root (Explorer, a Windows service) can't be frozen, and
	// freezing what it started would hang the desktop: everything the user
	// opened is a child of Explorer. Leave the whole family alone.
	if err := respond.CheckTarget(pid, tree[0].image); err != nil {
		res.failed, res.tree = []string{fmt.Sprintf("%s: %v; nothing it started was frozen either", filepath.Base(tree[0].image), err)}, 1
		res.took = time.Since(start)
		return res
	}
	c := containment{root: pid, image: image, at: start}
	for _, p := range tree {
		if err := respond.CheckTarget(p.pid, p.image); err != nil {
			res.failed = append(res.failed, fmt.Sprintf("%s: %v", filepath.Base(p.image), err))
			continue
		}
		did, err := s.suspendOnce(p.pid, p.image)
		if err != nil {
			res.failed = append(res.failed, fmt.Sprintf("%s: %v", filepath.Base(p.image), err))
			continue
		}
		if did {
			c.frozen = append(c.frozen, p)
		}
		res.frozen++
	}
	// A block the user already set stays theirs: Resume all only removes a
	// rule containment added.
	hadRule := false
	for _, r := range cfg.FirewallRules {
		if strings.EqualFold(ruleImage(r), image) {
			hadRule = true
		}
	}
	if name, err := blockProg(image); err == nil {
		res.blocked = true
		if !hadRule {
			c.rule = name
			_ = s.store.Update(func(cf *engine.Config) {
				for _, r := range cf.FirewallRules {
					if r == name {
						return
					}
				}
				cf.FirewallRules = append(cf.FirewallRules, name)
			})
		}
	} else {
		res.failed = append(res.failed, "internet block: "+err.Error())
	}
	res.took = time.Since(start)
	s.mu.Lock()
	if s.contained == nil {
		s.contained = map[uint32]containment{}
	}
	// A second trigger from the same program adds to the first record
	// (what's already frozen isn't frozen again), so Resume all still
	// undoes everything.
	if prev, ok := s.contained[pid]; ok && strings.EqualFold(prev.image, image) {
		prev.frozen = append(prev.frozen, c.frozen...)
		if prev.rule == "" {
			prev.rule = c.rule
		}
		c = prev
	}
	s.contained[pid] = c
	s.mu.Unlock()
	return res
}

// containNote is the sentence added to an alert about what containment did.
func containNote(image string, r containResult) string {
	name := image[strings.LastIndexAny(image, `\/`)+1:]
	others := r.tree - 1
	family := name
	if others > 0 {
		family = fmt.Sprintf("%s and %s it started", name, plural(others, "program"))
	}
	if r.practice {
		return fmt.Sprintf("Practice: with automatic containment on, Tripsilk would have frozen %s and blocked its internet. "+
			"Turn it on in Settings once a week of use shows no false alarms.", family)
	}
	msg := fmt.Sprintf("Tripsilk froze %s and blocked its internet within %d ms.", family, r.took.Milliseconds())
	if len(r.failed) > 0 {
		msg += " Not done: " + strings.Join(r.failed, "; ") + "."
	}
	return msg + " Resume all if this was you; otherwise end it and run a full scan."
}

// ResumeAll undoes a containment: resumes every program it froze and
// removes the internet block it added.
// What couldn't be undone stays recorded, so Resume all can be tried again.
func (s *Service) ResumeAll(pid uint32) error {
	s.mu.Lock()
	c, ok := s.contained[pid]
	delete(s.contained, pid)
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("Tripsilk didn't contain PID %d", pid)
	}
	var errs []string
	left := c
	left.frozen = nil
	for _, p := range c.frozen {
		if err := s.Resume(p.pid); err != nil {
			errs = append(errs, err.Error())
			left.frozen = append(left.frozen, p)
		}
	}
	if c.rule != "" {
		if err := s.Unblock(c.rule); err != nil {
			errs = append(errs, err.Error())
		} else {
			left.rule = ""
		}
	}
	if len(errs) > 0 {
		s.mu.Lock()
		if _, again := s.contained[pid]; !again {
			s.contained[pid] = left
		}
		s.mu.Unlock()
		return fmt.Errorf("partly undone (try Resume all again): %s", strings.Join(errs, "; "))
	}
	s.note("Containment undone", fmt.Sprintf("%s and the programs it started are running again, with internet access.", filepath.Base(c.image)))
	return nil
}

// SetAutoContain turns automatic containment on or off.
func (s *Service) SetAutoContain(on bool) error {
	if err := s.store.Update(func(c *engine.Config) { c.AutoContain = on }); err != nil {
		return err
	}
	if on {
		s.note("Automatic containment on", "A program that touches a trip line or acts like ransomware is frozen with everything it started, and cut off from the internet.")
	} else {
		s.note("Automatic containment off", "Tripsilk will record what it would freeze, without doing it.")
	}
	return nil
}
