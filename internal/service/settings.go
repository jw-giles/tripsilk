package service

import (
	"context"
	"time"

	"tripsilk/internal/engine"
)

const (
	configCheckEvery = 30 * time.Second
	// configFailLimit: consecutive failed checks before Tripsilk says so. One
	// failure is usually a passing file lock; a run of them can mean
	// something is holding the file to stop Tripsilk checking it.
	configFailLimit = 3
)

func (s *Service) startSettingsGuard(ctx context.Context) {
	go func() {
		t := time.NewTicker(configCheckEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.verifyConfig()
			}
		}
	}()
}

// verifyConfig puts Tripsilk's settings back if another program changed them.
func (s *Service) verifyConfig() {
	tampered, err := s.store.Verify()
	s.mu.Lock()
	if err != nil && !tampered {
		s.cfgFails++
	} else {
		s.cfgFails = 0
	}
	fails := s.cfgFails
	s.mu.Unlock()
	if fails == configFailLimit {
		s.Bus.Publish(engine.Alert{Severity: engine.SevMedium, Source: "system",
			Title:  "Tripsilk can't check its settings file",
			Detail: "Tripsilk couldn't read its settings file several times in a row (" + err.Error() + "). If this keeps happening, something may be holding the file open; run a full scan."})
	}
	if !tampered {
		return
	}
	detail := "Something other than Tripsilk edited or deleted its settings file. Tripsilk put its own settings back. " +
		"A program that changes a security tool's allow lists is usually trying to hide; run a full scan."
	if err != nil {
		detail += " Putting them back failed: " + err.Error()
	}
	s.Bus.Publish(engine.Alert{Severity: engine.SevHigh, Source: "system",
		Title: "Tripsilk's settings were changed by another program", Detail: detail, Actions: []string{"fullscan"},
		Summary: "Another program changed Tripsilk's settings. Tripsilk put them back.",
		Why:     "A program editing a security tool's allow lists is usually trying to hide.", Do: "fullscan"})
}
