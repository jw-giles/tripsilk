package service

import (
	"errors"
	"os"
	"strings"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/engine"
	"tripsilk/internal/evidence"
)

// inlineHashLimit: files up to this size are hashed while the alert is
// raised (a few milliseconds). Bigger ones are hashed in the background, and
// on demand from the dashboard, so a large program can't hold an alert up.
const inlineHashLimit = 16 << 20

// storeProcView publishes a read-only copy of the process table for
// enrich, which runs inside Publish and so can't take s.mu (some detectors
// publish while holding it). Caller holds s.mu.
func (s *Service) storeProcView(t map[uint32]agentguard.Proc) {
	v := make(map[uint32]evidence.Proc, len(t))
	for pid, p := range t {
		v[pid] = evidence.Proc{PID: p.PID, PPID: p.PPID, Image: p.Image, Created: p.Created}
	}
	s.procView.Store(&v)
}

// enrich adds the program's hash and parent chain to an alert about a
// program. It takes no Service locks.
func (s *Service) enrich(a *engine.Alert) {
	if a.Process == "" || a.Process == "System" {
		return
	}
	if a.Evidence == nil {
		a.Evidence = &engine.Evidence{}
	}
	e := a.Evidence
	if v := s.procView.Load(); v != nil && a.PID != 0 {
		if c := evidence.Chain(*v, a.PID, 8); len(c) > 0 && strings.EqualFold(c[0].Image, a.Process) {
			e.Chain = c
		}
	}
	if e.SHA256 != "" {
		return
	}
	// Sysmon's hash was taken when the program started, before its file
	// could be swapped, so it's the better evidence when there is one.
	if sum, ok := s.sysmonHash(a.PID, a.Process); ok {
		e.SHA256 = sum
		e.HashNote = "from Sysmon, taken when the program started"
		if now, ok := s.hasher.Cached(a.Process); ok && now != sum {
			e.HashNote += "; the file on disk has changed since (now " + now + ")"
		}
		return
	}
	if isNetworkPath(a.Process) {
		// Reading a file on another machine could stall every alert and
		// would make Tripsilk itself send traffic. The path is evidence
		// enough: programs rarely run from a share.
		e.HashNote = "not hashed: the program runs from a network share"
		return
	}
	fi, err := os.Stat(a.Process)
	switch {
	case err != nil:
		e.HashNote = "the program file couldn't be read: " + shortErr(err)
	case fi.Size() <= inlineHashLimit:
		if sum, err := s.hasher.SHA256(a.Process); err == nil {
			e.SHA256 = sum
		} else {
			e.HashNote = shortErr(err)
		}
	case fi.Size() > evidence.MaxHashSize:
		e.HashNote = "not hashed: the file is over 256 MB"
	default:
		if sum, ok := s.hasher.Cached(a.Process); ok {
			e.SHA256 = sum
		} else {
			e.HashNote = "large file; hashing in the background"
			s.hasher.HashLater(a.Process)
		}
	}
}

// isNetworkPath reports UNC paths (\\server\share\x.exe, \\?\UNC\...).
// Mapped drive letters can't be told apart without asking Windows, so
// they're hashed like local files.
func isNetworkPath(p string) bool {
	p = strings.ReplaceAll(p, "/", `\`)
	if strings.HasPrefix(strings.ToUpper(p), `\\?\UNC\`) {
		return true
	}
	return strings.HasPrefix(p, `\\`) && !strings.HasPrefix(p, `\\?\`) && !strings.HasPrefix(p, `\\.\`)
}

// FileHash returns a program's SHA-256 for the dashboard's "Check this
// program" button.
func (s *Service) FileHash(path string) (string, error) {
	if path == "" {
		return "", errors.New("no program file")
	}
	if isNetworkPath(path) {
		return "", errors.New("the program runs from a network share; Tripsilk doesn't read files from other machines")
	}
	return s.hasher.SHA256(path)
}

func shortErr(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
