package service

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/saiddid"
	"tripsilk/internal/win"
)

// "What it said vs what it did" for Claude Code (week 4): the shell
// commands in its session logs against the shells Tripsilk saw it start.
// First pass: shown on the Programs page, no alerts, until a week of real
// use shows how much of Claude Code's own housekeeping goes unexplained.

const (
	saidEvery  = 5 * time.Minute
	saidWindow = 24 * time.Hour
	maxShells  = 2000
)

type saidState struct {
	mu     sync.Mutex
	seen   []saiddid.Seen
	result *saiddid.Result
	at     time.Time
	root   string // Claude Code's projects folder (tests point it elsewhere)
}

var shellNames = map[string]bool{"bash.exe": true, "sh.exe": true, "cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "zsh.exe": true}

// isClaudeCode: the native claude.exe, or Node running the Claude Code
// package.
func isClaudeCode(agent agentguard.Proc) bool {
	base := strings.ToLower(winBase(agent.Image))
	return base == "claude.exe" || (base == "node.exe" && strings.Contains(strings.ToLower(agent.CmdLine), "claude-code"))
}

// noteShell records a shell Claude Code started directly.
func (s *Service) noteShell(agent agentguard.Proc, p agentguard.Proc, at time.Time) {
	if p.PPID != agent.PID || !shellNames[strings.ToLower(p.Name)] || !isClaudeCode(agent) {
		return
	}
	s.sd.mu.Lock()
	defer s.sd.mu.Unlock()
	s.sd.seen = append(s.sd.seen, saiddid.Seen{Time: at, PID: p.PID, Agent: agent.Image, Image: p.Image, CmdLine: p.CmdLine})
	if len(s.sd.seen) > maxShells {
		s.sd.seen = s.sd.seen[len(s.sd.seen)-maxShells:]
	}
}

func (s *Service) startSaidDid(ctx context.Context) {
	s.sd.mu.Lock()
	if s.sd.root == "" {
		s.sd.root = filepath.Join(win.Home(), ".claude", "projects")
	}
	s.sd.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(recapDelay):
		}
		s.every(ctx, saidEvery, s.compareSaidDid)
	}()
}

// compareSaidDid reads the logs changed in the last day and compares.
func (s *Service) compareSaidDid() {
	now := time.Now()
	since := now.Add(-saidWindow)
	s.sd.mu.Lock()
	root := s.sd.root
	var seen []saiddid.Seen
	for _, sh := range s.sd.seen {
		if sh.Time.After(since) {
			seen = append(seen, sh)
		}
	}
	s.sd.mu.Unlock()
	var sessions []saiddid.Session
	for _, f := range saiddid.Logs(root, since) {
		if sess, err := saiddid.ReadLog(f, since); err == nil || sess.Lines > 0 {
			sessions = append(sessions, sess)
		}
	}
	r := saiddid.Compare(sessions, seen)
	s.sd.mu.Lock()
	s.sd.result, s.sd.at = &r, now
	s.sd.mu.Unlock()
}

// SaidDid is shown on the Programs page.
type SaidDid struct {
	saiddid.Result
	At time.Time `json:"at"`
}

func (s *Service) saidDidSnapshot() *SaidDid {
	s.sd.mu.Lock()
	defer s.sd.mu.Unlock()
	if s.sd.result == nil {
		return nil
	}
	return &SaidDid{Result: *s.sd.result, At: s.sd.at}
}
