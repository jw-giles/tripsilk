package service

import (
	"context"
	"errors"
	"sync"
	"time"

	"tripsilk/internal/sysmon"
)

// Reading Sysmon (week 4), when a specialist already runs it. Its process,
// network and DNS events go into the journal as "sysmon" records, and its
// launch hashes are used as alert evidence. Tripsilk never installs or
// configures Sysmon.

const (
	sysmonEvery   = 2 * time.Second
	sysmonRecheck = 10 * time.Minute // when it isn't installed
	sysmonBatch   = 5000             // per read; the rest waits for the next
)

type sysmonState struct {
	mu        sync.Mutex
	installed bool
	events    uint64
	err       string
	hashes    *sysmon.Hashes
}

// SysmonStatus is shown in Settings.
type SysmonStatus struct {
	Installed bool   `json:"installed"`
	Events    uint64 `json:"events"`
	Error     string `json:"error,omitempty"`
}

func (s *Service) sysmonStatus() SysmonStatus {
	s.sm.mu.Lock()
	defer s.sm.mu.Unlock()
	return SysmonStatus{Installed: s.sm.installed, Events: s.sm.events, Error: s.sm.err}
}

// sysmonHash is Sysmon's launch hash for a running program. No Service
// locks: it's called from enrich.
func (s *Service) sysmonHash(pid uint32, image string) (string, bool) {
	s.sm.mu.Lock()
	defer s.sm.mu.Unlock()
	if s.sm.hashes == nil || pid == 0 {
		return "", false
	}
	return s.sm.hashes.Get(pid, image)
}

func (s *Service) startSysmon(ctx context.Context) {
	s.sm.mu.Lock()
	s.sm.hashes = sysmon.NewHashes(8192)
	s.sm.mu.Unlock()
	go func() {
		var last uint64
		started := false
		wait := time.Duration(0)
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			if !started {
				id, err := sysmon.Latest()
				if err != nil {
					s.setSysmon(false, err)
					wait = sysmonRecheck
					continue
				}
				last, started = id, true // from now: history is Sysmon's to keep
				s.setSysmon(true, nil)
			}
			evs, next, err := sysmon.Since(last, sysmonBatch)
			last = next
			if errors.Is(err, sysmon.ErrNotInstalled) {
				started = false
				s.setSysmon(false, err)
				wait = sysmonRecheck
				continue
			}
			s.onSysmon(evs, err)
			wait = sysmonEvery
		}
	}()
}

func (s *Service) setSysmon(installed bool, err error) {
	s.sm.mu.Lock()
	defer s.sm.mu.Unlock()
	s.sm.installed = installed
	s.sm.err = ""
	if err != nil && !errors.Is(err, sysmon.ErrNotInstalled) {
		s.sm.err = err.Error()
	}
}

func (s *Service) onSysmon(evs []sysmon.Event, err error) {
	s.mu.Lock()
	j := s.sn.j
	s.mu.Unlock()
	s.sm.mu.Lock()
	s.sm.events += uint64(len(evs))
	s.sm.err = ""
	if err != nil {
		s.sm.err = err.Error()
	}
	for _, ev := range evs {
		if ev.ID == 1 {
			s.sm.hashes.Add(ev.PID, ev.Image, ev.SHA256)
		}
	}
	s.sm.mu.Unlock()
	if j != nil {
		for _, ev := range evs {
			j.Write("sysmon", ev)
		}
	}
}
