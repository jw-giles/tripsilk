package service

import (
	"fmt"
	"path/filepath"
	"strings"

	"tripsilk/internal/canary"
	"tripsilk/internal/engine"
	"tripsilk/internal/eventlog"
	"tripsilk/internal/notify"
	"tripsilk/internal/respond"
	"tripsilk/internal/sensor"
	"tripsilk/internal/win"
)

// installedUnder reports whether exe sits inside programFiles. Only that copy
// may start itself as admin at sign-in: Program Files can't be changed
// without admin rights, while a dev build's folder (C:\Tripsilk\build\bin) can
// be, so a program could swap the dev Tripsilk.exe for itself and be started
// as admin.
func installedUnder(exe, programFiles string) bool {
	if exe == "" || programFiles == "" {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(programFiles), filepath.Clean(exe))
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

func isInstalledCopy(exe string) bool {
	pf := win.ProgramFiles()
	// Windows paths compare case-insensitively.
	return installedUnder(strings.ToLower(exe), strings.ToLower(pf))
}

// errNotInstalled explains why a dev build won't start itself at sign-in.
var errNotInstalled = fmt.Errorf("start at sign-in only works for the installed Tripsilk (in Program Files). " +
	"This copy runs from a folder ordinary programs can change, and Windows would start it as admin")

// Cleanup undoes what Tripsilk changed outside its own settings folder, for the
// uninstaller: it resumes processes Tripsilk suspended, removes the firewall
// rules it added (including the emergency block, so uninstalling never
// leaves the PC offline), removes the read-audit rules it put on bait files,
// and deletes the sign-in task. Settings stay in place. It returns
// everything that couldn't be undone.
func Cleanup(dataDir string) []error {
	store, err := engine.OpenStore(dataDir)
	if err != nil {
		return []error{fmt.Errorf("open settings: %w", err)}
	}
	cfg := store.Get()
	var errs []error
	for _, r := range cfg.Suspended {
		if !strings.EqualFold(imagePath(r.PID), r.Image) {
			continue // exited, or the PID now belongs to something else
		}
		if err := respond.Resume(r.PID, r.Image); err != nil {
			errs = append(errs, fmt.Errorf("resume %s (PID %d): %w", r.Image, r.PID, err))
		}
	}
	for _, rule := range cfg.FirewallRules {
		if err := respond.Unblock(rule); err != nil {
			errs = append(errs, fmt.Errorf("remove firewall rule %q: %w", rule, err))
		}
	}
	if respond.OutboundBlocked() {
		if err := respond.UnblockAllOutbound(); err != nil {
			errs = append(errs, fmt.Errorf("remove emergency internet block: %w", err))
		}
	}
	if cfg.ReadAuditing && len(cfg.BaitFiles) > 0 {
		if bad, err := canary.RemoveReadAudit(cfg.BaitFiles); err != nil {
			errs = append(errs, fmt.Errorf("remove bait audit rules: %w", err))
		} else {
			for p, why := range bad {
				errs = append(errs, fmt.Errorf("remove audit rule from %s: %s", p, why))
			}
		}
	}
	if notify.StartsAtSignIn() {
		if err := notify.SetStartAtSignIn(false, ""); err != nil {
			errs = append(errs, err)
		}
	}
	if cfg.EventLogCopy {
		if err := eventlog.Unregister(); err != nil {
			errs = append(errs, err)
		}
	}
	// The event-tracing sessions: Tripsilk's own, and the self-test's in case
	// one was interrupted.
	sensor.StopSession(SensorSession)
	sensor.StopSession("Tripsilk Selftest Sensor")
	_ = store.Update(func(c *engine.Config) {
		c.Suspended = nil
		c.FirewallRules = nil
		c.ReadAuditing = false
		c.EventLogCopy = false
	})
	return errs
}
