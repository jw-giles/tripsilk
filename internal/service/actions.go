package service

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"tripsilk/internal/canary"
	"tripsilk/internal/defender"
	"tripsilk/internal/engine"
	"tripsilk/internal/notify"
	"tripsilk/internal/respond"
)

// Every user action publishes an info alert so the feed is an audit trail.

func (s *Service) note(title, detail string) {
	s.Bus.Publish(engine.Alert{Severity: engine.SevInfo, Source: "system", Title: title, Detail: detail})
}

func (s *Service) dryRun() bool { return s.store.Get().DryRun }

func (s *Service) AddBait(path string) error {
	if err := s.reg.Add(path); err != nil {
		return err
	}
	clean := filepath.Clean(path)
	if err := s.store.Update(func(c *engine.Config) {
		for _, p := range c.BaitFiles {
			if strings.EqualFold(p, clean) {
				return
			}
		}
		c.BaitFiles = append(c.BaitFiles, clean)
	}); err != nil {
		return err
	}
	if s.store.Get().ReadAuditing {
		_ = canary.EnableReadAuditing([]string{clean})
	}
	if err := s.watcher.Sync(); err != nil {
		return err
	}
	s.note("Trip line added", clean)
	return nil
}

func (s *Service) RemoveBait(path string) error {
	s.reg.Remove(path)
	err := s.store.Update(func(c *engine.Config) {
		out := c.BaitFiles[:0]
		for _, p := range c.BaitFiles {
			if !strings.EqualFold(p, filepath.Clean(path)) {
				out = append(out, p)
			}
		}
		c.BaitFiles = out
	})
	if err == nil {
		s.note("Trip line removed", path)
	}
	return err
}

func (s *Service) SetReadAuditing(on bool) error {
	if on {
		paths := make([]string, 0)
		for _, w := range s.reg.List() {
			paths = append(paths, w.Path)
		}
		if err := canary.EnableReadAuditing(paths); err != nil {
			return err
		}
	}
	return s.store.Update(func(c *engine.Config) { c.ReadAuditing = on })
}

func (s *Service) SetDryRun(on bool) error {
	return s.store.Update(func(c *engine.Config) { c.DryRun = on })
}

func (s *Service) Allow(image string) error {
	if err := s.store.Allow(image); err != nil {
		return err
	}
	s.note("Allowed to use AI", image)
	return nil
}

func (s *Service) Disallow(image string) error {
	if err := s.store.Disallow(image); err != nil {
		return err
	}
	s.note("Removed from allowed list", image)
	return nil
}

func (s *Service) Suspend(pid uint32, image string) error {
	if err := respond.CheckTarget(pid, image); err != nil {
		return err
	}
	if s.dryRun() {
		s.note("Dry run: would suspend", fmt.Sprintf("%s (PID %d)", image, pid))
		return nil
	}
	did, err := s.suspendOnce(pid, image)
	if err != nil || !did {
		return err
	}
	s.note("Process suspended", fmt.Sprintf("%s (PID %d). Resume it from the dashboard if this was a mistake.", image, pid))
	return nil
}

func (s *Service) Resume(pid uint32) error {
	s.mu.Lock()
	image, ok := s.suspended[pid]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("PID %d was not suspended by Tripsilk", pid)
	}
	if err := resumeProc(pid, image); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.suspended, pid)
	s.mu.Unlock()
	s.saveSuspended()
	s.note("Process resumed", fmt.Sprintf("%s (PID %d)", image, pid))
	return nil
}

func (s *Service) Block(image string) error {
	if s.dryRun() {
		s.note("Dry run: would block internet access", image)
		return nil
	}
	name, err := blockProg(image)
	if err != nil {
		return err
	}
	if err := s.store.Update(func(c *engine.Config) {
		for _, r := range c.FirewallRules {
			if r == name {
				return
			}
		}
		c.FirewallRules = append(c.FirewallRules, name)
	}); err != nil {
		return err
	}
	s.note("Internet access blocked", image)
	return nil
}

func (s *Service) Unblock(rule string) error {
	if err := unblockRule(rule); err != nil {
		return err
	}
	if err := s.store.Update(func(c *engine.Config) {
		out := c.FirewallRules[:0]
		for _, r := range c.FirewallRules {
			if r != rule {
				out = append(out, r)
			}
		}
		c.FirewallRules = out
	}); err != nil {
		return err
	}
	s.note("Internet access restored", ruleImage(rule))
	return nil
}

// Scan starts a Defender scan in the background. Only one at a time.
func (s *Service) Scan(kind defender.ScanType) error {
	s.mu.Lock()
	if s.scanning != "" {
		s.mu.Unlock()
		return fmt.Errorf("a %s is already running", s.scanning)
	}
	s.scanning = string(kind)
	s.mu.Unlock()
	s.note("Defender scan started", string(kind))
	go func() {
		err := defender.StartScan(kind)
		s.mu.Lock()
		s.scanning = ""
		s.mu.Unlock()
		if err != nil {
			s.Bus.Publish(engine.Alert{Severity: engine.SevMedium, Source: "defender",
				Title: "Scan failed", Detail: err.Error()})
		} else {
			s.note("Defender scan finished", string(kind)+". Any detections appear under Defender.")
		}
		s.refreshDefender()
	}()
	return nil
}

func (s *Service) UpdateSignatures() error {
	if err := defender.UpdateSignatures(); err != nil {
		return err
	}
	s.note("Virus definitions updated", "")
	s.refreshDefender()
	return nil
}

// Acknowledge marks current critical and high alerts as handled, so the
// status wall clears once the user has dealt with them. The alerts stay
// in the feed.
func (s *Service) Acknowledge() {
	s.mu.Lock()
	s.ackedAt = time.Now()
	s.mu.Unlock()
	s.note("Marked as handled", "Earlier alerts stay in this list for reference.")
}

func (s *Service) saveSuspended() {
	s.mu.Lock()
	recs := make([]engine.SuspendedRecord, 0, len(s.suspended))
	for pid, img := range s.suspended {
		recs = append(recs, engine.SuspendedRecord{PID: pid, Image: img})
	}
	s.mu.Unlock()
	_ = s.store.Update(func(c *engine.Config) { c.Suspended = recs })
}

// restoreSuspended re-lists suspensions from a previous run, keeping only
// those whose PID still belongs to the same program (a reboot or exit
// recycles PIDs).
func (s *Service) restoreSuspended(recs []engine.SuspendedRecord) {
	s.mu.Lock()
	for _, r := range recs {
		if strings.EqualFold(imagePath(r.PID), r.Image) {
			s.suspended[r.PID] = r.Image
		}
	}
	s.mu.Unlock()
	s.saveSuspended()
}

// toast shows a Windows notification for high and critical alerts.
func (s *Service) toast(a engine.Alert) {
	if a.Severity != engine.SevHigh && a.Severity != engine.SevCritical {
		return
	}
	if s.store.Get().MuteToasts {
		return
	}
	ok, suppressed := s.toasts.Allow(time.Now())
	if !ok {
		return
	}
	body := a.Detail
	if suppressed > 0 {
		body = fmt.Sprintf("(+%d more in Tripsilk) %s", suppressed, body)
	}
	go func() {
		if err := notify.Toast("Tripsilk: "+a.Title, body); err != nil {
			s.mu.Lock()
			first := !s.toastErr
			s.toastErr = true
			s.mu.Unlock()
			if first && !errors.Is(err, engine.ErrUnsupported) {
				s.note("Windows notifications aren't working", err.Error()+" Alerts still appear here.")
			}
		}
	}()
}

func (s *Service) SetToasts(on bool) error {
	return s.store.Update(func(c *engine.Config) { c.MuteToasts = !on })
}

// SetStartAtSignIn creates or removes the sign-in task.
func (s *Service) SetStartAtSignIn(on bool) error {
	if on && !s.installed {
		return errNotInstalled
	}
	if err := notify.SetStartAtSignIn(on, s.dataDir); err != nil {
		return err
	}
	s.mu.Lock()
	s.signIn = notify.StartsAtSignIn()
	s.mu.Unlock()
	if on {
		s.note("Tripsilk will start when you sign in", "Uses a scheduled task named "+notify.TaskName+".")
	} else {
		s.note("Tripsilk won't start at sign-in", "")
	}
	return nil
}

// LockToCurrent limits an app to the AI services it is using right now.
func (s *Service) LockToCurrent(image string) error {
	s.mu.Lock()
	var services []string
	for _, f := range s.tracker.Snapshot() {
		if !f.Local && strings.EqualFold(f.Image, image) {
			services = append(services, f.Provider)
		}
	}
	s.mu.Unlock()
	if len(services) == 0 {
		return fmt.Errorf("%s isn't connected to any AI service right now, so there's nothing to lock it to", filepath.Base(image))
	}
	if err := s.store.SetServiceRule(image, services); err != nil {
		return err
	}
	rule, _ := s.store.ServiceRule(image)
	s.note("Rule set", fmt.Sprintf("%s may use only %s. Anything else raises an alert.", filepath.Base(image), strings.Join(rule, ", ")))
	return nil
}

// AllowService adds a service to an app's existing rule.
func (s *Service) AllowService(image, service string) error {
	rule, ok := s.store.ServiceRule(image)
	if !ok {
		return fmt.Errorf("%s has no rule to add to", filepath.Base(image))
	}
	if err := s.store.SetServiceRule(image, append(rule, service)); err != nil {
		return err
	}
	s.note("Rule updated", fmt.Sprintf("%s may now also use %s.", filepath.Base(image), service))
	return nil
}

// ClearServiceRule lets an app use any AI service again.
func (s *Service) ClearServiceRule(image string) error {
	if err := s.store.ClearServiceRule(image); err != nil {
		return err
	}
	s.note("Rule removed", filepath.Base(image)+" may use any AI service again.")
	return nil
}

// suspendOnce suspends a process unless Tripsilk already has it suspended.
// Windows counts suspends (a second one needs two resumes) while the
// dashboard tracks one, so the check and the reservation happen under one
// lock: the shield and a user click at the same moment can't both suspend.
// A recorded PID whose program differs was recycled by Windows: the stale
// entry is dropped and the new process is treated as new.
func (s *Service) suspendOnce(pid uint32, image string) (bool, error) {
	s.mu.Lock()
	if prev, ok := s.suspended[pid]; ok {
		if strings.EqualFold(prev, image) {
			s.mu.Unlock()
			return false, nil
		}
		delete(s.suspended, pid)
	}
	s.suspended[pid] = image // reserve
	s.mu.Unlock()
	if err := suspendProc(pid, image); err != nil {
		s.mu.Lock()
		delete(s.suspended, pid)
		s.mu.Unlock()
		return false, err
	}
	s.saveSuspended()
	return true, nil
}

// The response actions, as variables so tests can stand in for Windows.
var (
	suspendProc = respond.Suspend
	resumeProc  = respond.Resume
	blockProg   = respond.Block
	unblockRule = respond.Unblock
)

// ruleImage is the program a Tripsilk firewall rule blocks.
func ruleImage(rule string) string {
	if img, ok := respond.OwnRule(rule); ok {
		return img
	}
	return rule
}
