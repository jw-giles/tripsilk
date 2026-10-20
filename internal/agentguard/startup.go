package agentguard

import (
	"encoding/xml"
	"io"
	"sort"
	"strings"
	"unicode/utf16"
)

// StartupEntry is something configured to run automatically.
type StartupEntry struct {
	Where   string `json:"where"` // "Run key (current user)", "Startup folder", "Scheduled task"
	Name    string `json:"name"`
	Command string `json:"command"` // command line, file path, or task path
}

func (e StartupEntry) id() string { return e.Where + "|" + e.Name }

// StartupWatch reports entries that appear or change after the baseline.
type StartupWatch struct {
	known map[string]StartupEntry
	init  bool
}

func NewStartupWatch() *StartupWatch { return &StartupWatch{known: map[string]StartupEntry{}} }

// Check compares the current entries with the previous call. The first call
// records a baseline. Sources that failed to read (nil slice with ok=false)
// keep their previous entries so a transient read error can't hide or
// re-announce anything.
func (w *StartupWatch) Check(current map[string][]StartupEntry, failed map[string]bool) (added []StartupEntry) {
	next := map[string]StartupEntry{}
	for id, e := range w.known {
		if failed[e.Where] {
			next[id] = e
		}
	}
	for _, entries := range current {
		for _, e := range entries {
			next[e.id()] = e
			if !w.init {
				continue
			}
			if old, ok := w.known[e.id()]; !ok || old.Command != e.Command {
				added = append(added, e)
			}
		}
	}
	w.known = next
	w.init = true
	sort.Slice(added, func(i, j int) bool { return added[i].id() < added[j].id() })
	return added
}

// Count is the number of entries currently known.
func (w *StartupWatch) Count() int { return len(w.known) }

// taskCommand extracts the Exec actions from a task XML file, which Windows
// stores as UTF-16 with a byte order mark.
func taskCommand(data []byte) string {
	text := decodeUTF16(data)
	var task struct {
		Actions struct {
			Exec []struct {
				Command   string `xml:"Command"`
				Arguments string `xml:"Arguments"`
			} `xml:"Exec"`
		} `xml:"Actions"`
	}
	dec := xml.NewDecoder(strings.NewReader(text))
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := dec.Decode(&task); err != nil {
		return ""
	}
	var parts []string
	for _, e := range task.Actions.Exec {
		parts = append(parts, strings.TrimSpace(e.Command+" "+e.Arguments))
	}
	if len(parts) == 0 {
		return "(no program: COM or built-in action)"
	}
	return strings.Join(parts, "; ")
}

func decodeUTF16(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		b = b[2:]
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		}
		return string(utf16.Decode(u))
	}
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	return string(b)
}
