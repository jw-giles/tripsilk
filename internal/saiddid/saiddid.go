// Package saiddid compares what Claude Code said it would run (the shell
// commands in its session logs) with the shells Tripsilk saw it start. A
// shell started by Claude Code that matches no command in its log is
// "unexplained": it may be Claude Code's own housekeeping, or something
// that steered it outside its conversation. When the log format isn't
// recognized, the answer is "can't compare", never an alarm. Standard
// library only.
package saiddid

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Said is one shell command in a session log.
type Said struct {
	Session string    `json:"session"`
	Time    time.Time `json:"time"`
	Tool    string    `json:"tool"` // Bash or PowerShell
	Command string    `json:"command"`
}

// Seen is one shell Tripsilk saw an agent start directly.
type Seen struct {
	Time    time.Time `json:"time"`
	PID     uint32    `json:"pid"`
	Agent   string    `json:"agent"` // the agent program
	Image   string    `json:"image"`
	CmdLine string    `json:"cmdLine"`
}

// Session is one Claude Code session's log, as read.
type Session struct {
	ID    string    `json:"id"`
	File  string    `json:"file"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	Lines int       `json:"lines"`
	Said  []Said    `json:"-"`
}

// shellTools are the Claude Code tools that run a shell.
var shellTools = map[string]bool{"Bash": true, "PowerShell": true}

// ReadLog reads one session log (JSONL). Lines that don't parse are
// skipped; a log with lines but no recognizable entries is reported by the
// caller as "can't compare".
func ReadLog(path string, since time.Time) (Session, error) {
	f, err := os.Open(path)
	if err != nil {
		return Session{}, err
	}
	defer f.Close()
	s := Session{File: path, ID: strings.TrimSuffix(filepath.Base(path), ".jsonl")}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256<<10), 32<<20)
	for sc.Scan() {
		s.Lines++
		var line struct {
			Type      string    `json:"type"`
			Timestamp time.Time `json:"timestamp"`
			SessionID string    `json:"sessionId"`
			Message   struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil || line.Timestamp.IsZero() {
			continue
		}
		if s.First.IsZero() || line.Timestamp.Before(s.First) {
			s.First = line.Timestamp
		}
		if line.Timestamp.After(s.Last) {
			s.Last = line.Timestamp
		}
		if line.SessionID != "" {
			s.ID = line.SessionID
		}
		if line.Type != "assistant" || line.Timestamp.Before(since) {
			continue
		}
		var parts []struct {
			Type  string `json:"type"`
			Name  string `json:"name"`
			Input struct {
				Command string `json:"command"`
			} `json:"input"`
		}
		if json.Unmarshal(line.Message.Content, &parts) != nil {
			continue // a plain-text message
		}
		for _, p := range parts {
			if p.Type == "tool_use" && shellTools[p.Name] && p.Input.Command != "" {
				s.Said = append(s.Said, Said{Session: s.ID, Time: line.Timestamp, Tool: p.Name, Command: p.Input.Command})
			}
		}
	}
	return s, sc.Err()
}

// Logs lists Claude Code session logs under root (its projects folder)
// changed since t.
func Logs(root string, since time.Time) []string {
	var out []string
	dirs, _ := os.ReadDir(root)
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, _ := os.ReadDir(filepath.Join(root, d.Name()))
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".jsonl") || !f.Type().IsRegular() {
				continue
			}
			if fi, err := f.Info(); err == nil && fi.ModTime().After(since) {
				out = append(out, filepath.Join(root, d.Name(), f.Name()))
			}
		}
	}
	sort.Strings(out)
	return out
}

// Result is a comparison over a time window.
type Result struct {
	Status      string `json:"status"` // "ok", "no-logs", "cant-compare"
	Why         string `json:"why,omitempty"`
	Sessions    int    `json:"sessions"`
	Said        int    `json:"said"`        // shell commands in the logs
	Matched     int    `json:"matched"`     // of those, seen running
	Seen        int    `json:"seen"`        // shells Claude Code started while a session was active
	Unexplained []Seen `json:"unexplained"` // seen, matching nothing said (newest first, at most 20)
}

// Window: a shell may start a little before its log line is written, or
// long after (the user approved it later).
const (
	early  = 5 * time.Second
	late   = 15 * time.Minute
	active = 2 * time.Minute // a session counts as active this long around its log lines
)

// minToJudge: shells needed before "nothing matched" means the
// comparison doesn't work, rather than one odd shell.
const minToJudge = 5

// Compare matches seen shells with said commands. Each said command
// explains at most one shell.
func Compare(sessions []Session, seen []Seen) Result {
	r := Result{Status: "ok", Sessions: len(sessions)}
	if len(sessions) == 0 {
		return Result{Status: "no-logs", Why: "No Claude Code session logs changed in this period."}
	}
	var said []Said
	lines := 0
	for _, s := range sessions {
		said = append(said, s.Said...)
		lines += s.Lines
	}
	known := 0
	for _, s := range sessions {
		if !s.First.IsZero() {
			known++
		}
	}
	if known == 0 && lines > 0 {
		return Result{Status: "cant-compare", Sessions: len(sessions),
			Why: "Claude Code's session logs are there but Tripsilk doesn't recognize their format (it may have changed in an update)."}
	}
	r.Said = len(said)
	sort.Slice(said, func(i, j int) bool { return said[i].Time.Before(said[j].Time) })
	used := make([]bool, len(said))
	inSession := func(t time.Time) bool {
		for _, s := range sessions {
			if !s.First.IsZero() && !t.Before(s.First.Add(-active)) && !t.After(s.Last.Add(late)) {
				return true
			}
		}
		return false
	}
	sort.Slice(seen, func(i, j int) bool { return seen[i].Time.Before(seen[j].Time) })
	for _, sh := range seen {
		if !inSession(sh.Time) || housekeeping(sh.CmdLine) {
			continue
		}
		r.Seen++
		obs := normalizeSeen(sh.CmdLine)
		hit := -1
		for i, c := range said {
			if used[i] || sh.Time.Before(c.Time.Add(-early)) || sh.Time.After(c.Time.Add(late)) {
				continue
			}
			if matches(obs, c.Command) {
				hit = i
				break
			}
		}
		if hit >= 0 {
			used[hit] = true
			r.Matched++
		} else {
			r.Unexplained = append(r.Unexplained, sh)
		}
	}
	// Many shells and not one match means the commands don't show in the
	// shells' command lines here (Claude Code may pass them another way):
	// say so rather than call every shell unexplained.
	if r.Seen >= minToJudge && r.Matched == 0 && r.Said > 0 {
		return Result{Status: "cant-compare", Sessions: r.Sessions, Said: r.Said, Seen: r.Seen,
			Why: "Claude Code's commands don't appear in the command lines of the shells it starts, so they can't be matched."}
	}
	sort.Slice(r.Unexplained, func(i, j int) bool { return r.Unexplained[i].Time.After(r.Unexplained[j].Time) })
	if len(r.Unexplained) > 20 {
		r.Unexplained = r.Unexplained[:20]
	}
	return r
}

// housekeeping: shells Claude Code starts for itself (capturing the user's
// shell environment), which no log line asks for.
func housekeeping(cmd string) bool {
	c := strings.ToLower(cmd)
	return strings.Contains(c, "shell-snapshots") || strings.Contains(c, "snapshot-bash") || strings.Contains(c, "snapshot-zsh")
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// normalizeSeen undoes the quoting a shell's command line wraps the
// command in ('\” and '"'"' for a single quote, \" for a double quote).
func normalizeSeen(cmd string) string {
	r := strings.NewReplacer(`'\''`, `'`, `'"'"'`, `'`, `\"`, `"`, `\\`, `\`)
	return collapse(r.Replace(cmd))
}

// matches: the shell's command line contains the start of the command, or
// (for a command too long or re-quoted beyond recognition) its first
// distinctive words in order.
func matches(obs, said string) bool {
	s := collapse(said)
	if s == "" {
		return false
	}
	head := s
	if len(head) > 48 {
		head = head[:48]
	}
	if strings.Contains(obs, head) {
		return true
	}
	var words []string
	for _, w := range strings.Fields(s) {
		w = strings.Trim(w, `'"`)
		if len(w) >= 3 {
			words = append(words, w)
		}
		if len(words) == 4 {
			break
		}
	}
	if len(words) < 2 {
		return false
	}
	at := 0
	for _, w := range words {
		i := strings.Index(obs[at:], w)
		if i < 0 {
			return false
		}
		at += i + len(w)
	}
	return true
}
