package traffic

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"tripsilk/internal/engine"
)

// Seen remembers which app has talked to which organization, so a first
// contact can be shown as new. During the learning period nothing is new:
// everything a PC does in its first days is its baseline.
type Seen struct {
	mu       sync.Mutex
	path     string
	learning time.Duration
	glow     time.Duration
	maxPairs int
	data     seenFile
	dirty    bool
}

type seenFile struct {
	Started time.Time            `json:"started"`
	Pairs   map[string]time.Time `json:"pairs"` // "appKey|org" -> first seen
}

func OpenSeen(path string, learning, glow time.Duration) (*Seen, error) {
	s := &Seen{path: path, learning: learning, glow: glow, maxPairs: 20000,
		data: seenFile{Pairs: map[string]time.Time{}}}
	b, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(b, &s.data) != nil {
			s.data = seenFile{Pairs: map[string]time.Time{}}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if s.data.Pairs == nil {
		s.data.Pairs = map[string]time.Time{}
	}
	if s.data.Started.IsZero() {
		s.data.Started = time.Now()
		s.dirty = true
	}
	return s, nil
}

// Learning reports whether the baseline period is still running, and when
// it ends.
func (s *Seen) Learning(now time.Time) (bool, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	end := s.data.Started.Add(s.learning)
	return now.Before(end), end
}

// Novel records a pair and reports whether it is new: first seen after the
// learning period and within the glow window.
func (s *Seen) Novel(appKey, org string, now time.Time) bool {
	k := appKey + "|" + org
	s.mu.Lock()
	defer s.mu.Unlock()
	first, ok := s.data.Pairs[k]
	if !ok {
		if len(s.data.Pairs) >= s.maxPairs {
			return false // full: stop learning rather than evict history
		}
		first = now
		s.data.Pairs[k] = first
		s.dirty = true
	}
	return first.After(s.data.Started.Add(s.learning)) && now.Sub(first) < s.glow
}

// Save writes the store if it changed.
func (s *Seen) Save() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(s.data)
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return engine.WriteFileAtomic(s.path, b)
}
