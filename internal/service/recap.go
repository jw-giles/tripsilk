package service

import (
	"context"
	"time"

	"tripsilk/internal/journal"
	"tripsilk/internal/recap"
)

// The weekly summary on Home (week 4), summed from the event journal.

const (
	recapWindow = 7 * 24 * time.Hour
	recapEvery  = 3 * time.Hour
	recapDelay  = 90 * time.Second // after start, so it doesn't slow startup
)

func (s *Service) startRecap(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(recapDelay):
		}
		s.every(ctx, recapEvery, s.buildRecap)
	}()
}

// buildRecap re-sums the last week. It runs in the background and only
// one at a time.
func (s *Service) buildRecap() {
	if !s.recapMu.TryLock() {
		return
	}
	defer s.recapMu.Unlock()
	s.mu.Lock()
	j := s.sn.j
	s.mu.Unlock()
	if j == nil {
		return
	}
	_ = j.Flush()
	now := time.Now()
	r := recap.Build(j.Dir(), journal.Files(j.Dir()), now.Add(-recapWindow), now)
	s.recap.Store(&r)
}

// RefreshRecap re-sums the week now, for the "Update" link on Home.
func (s *Service) RefreshRecap() {
	s.buildRecap()
}

// recapSnapshot is the latest summary, nil before the first one.
func (s *Service) recapSnapshot() *recap.Recap {
	return s.recap.Load()
}
