// Package canary watches files the user has designated as bait. The user
// supplies the files; Tripsilk does not fabricate credentials or secrets. A
// bait file is something the user is willing to treat as a tripwire: a
// document named to look interesting to an intruder, placed where normal
// work never touches it.
//
// Detection on Windows:
//   - Modify / rename / delete: a directory watcher (ReadDirectoryChangesW,
//     wired in canary_windows.go) fires on any change to a watched file. Needs
//     no privileges, but cannot name the responsible process.
//   - Read: object-access auditing. When enabled and running as administrator,
//     the watcher polls the Security event log for 4663 read events on watched
//     paths, which name the process. Read detection is best-effort and the UI
//     says so when auditing is unavailable.
//
// This file holds the platform-independent watch registry and event types;
// canary_windows.go / canary_other.go provide the OS watcher.
package canary

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// EventKind describes what happened to a bait file.
type EventKind string

const (
	Modified EventKind = "modified"
	Deleted  EventKind = "deleted"
	Renamed  EventKind = "renamed"
	// Replaced: saved over. Most editors (Notepad, VS Code, Word) save by
	// writing a new copy and swapping it in, which Windows reports as the
	// file being removed and/or a new file appearing at the same path.
	Replaced EventKind = "replaced"
	Read     EventKind = "read"
)

// Event is one tripwire hit.
type Event struct {
	Path    string    `json:"path"`
	Kind    EventKind `json:"kind"`
	When    time.Time `json:"when"`
	PID     uint32    `json:"pid,omitempty"`     // read events only, when auditing names it
	Process string    `json:"process,omitempty"` // read events only
}

// Watch is a registered bait file.
type Watch struct {
	Path  string    `json:"path"`
	Added time.Time `json:"added"`
}

// Registry holds the set of watched bait files. The OS watcher reads it to
// decide which change notifications matter.
type Registry struct {
	mu      sync.RWMutex
	watches map[string]Watch // keyed by cleaned, lowercased path
}

func NewRegistry() *Registry { return &Registry{watches: map[string]Watch{}} }

func key(path string) string { return strings.ToLower(filepath.Clean(path)) }

// Add registers an existing file as bait. The file must already exist — the
// user creates the bait, Tripsilk only watches it.
func (r *Registry) Add(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("bait must be a file, not a directory")
	}
	r.mu.Lock()
	r.watches[key(path)] = Watch{Path: filepath.Clean(path), Added: time.Now()}
	r.mu.Unlock()
	return nil
}

func (r *Registry) Remove(path string) {
	r.mu.Lock()
	delete(r.watches, key(path))
	r.mu.Unlock()
}

// Has reports whether a path (in any case) is watched.
func (r *Registry) Has(path string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.watches[key(path)]
	return ok
}

// List returns watched files sorted by path.
func (r *Registry) List() []Watch {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Watch, 0, len(r.watches))
	for _, w := range r.watches {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Dirs returns the distinct parent directories of watched files, which is what
// a directory-change watcher subscribes to.
func (r *Registry) Dirs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[string]bool{}
	var dirs []string
	for _, w := range r.watches {
		d := filepath.Dir(w.Path)
		if lk := strings.ToLower(d); !seen[lk] {
			seen[lk] = true
			dirs = append(dirs, d)
		}
	}
	sort.Strings(dirs)
	return dirs
}

// systemReaders are Windows components that read files as part of normal
// scanning and indexing. Their reads of a bait file are expected and are not
// reported. Matched on image base name.
var systemReaders = map[string]bool{
	"msmpeng.exe": true, "mpdefendercoreservice.exe": true, "nissrv.exe": true,
	"mpcopyaccelerator.exe": true, "searchprotocolhost.exe": true,
	"searchindexer.exe": true, "searchfilterhost.exe": true,
}

// IsSystemReader reports whether a process path is an expected scanner.
func IsSystemReader(image string) bool {
	return systemReaders[strings.ToLower(filepath.Base(strings.ReplaceAll(image, `\`, "/")))]
}

// Windows directory-change action codes (FILE_ACTION_*).
const (
	ActAdded      = 1
	ActRemoved    = 2
	ActModified   = 3
	ActRenamedOld = 4
	ActRenamedNew = 5
)

// Coalesce turns the actions seen for one watched path in one notification
// batch into a single event kind ("" for nothing to report).
//   - something appearing at the path (added, or renamed onto it) = Replaced:
//     the path still holds a file, but not the one that was there
//   - removed with nothing after = Deleted
//   - renamed away = Renamed
//   - written in place = Modified
func Coalesce(actions []uint32) EventKind {
	var appeared, removed, renamedAway, modified bool
	for _, a := range actions {
		switch a {
		case ActAdded, ActRenamedNew:
			appeared = true
		case ActRemoved:
			removed = true
		case ActRenamedOld:
			renamedAway = true
		case ActModified:
			modified = true
		}
	}
	last := uint32(0)
	if len(actions) > 0 {
		last = actions[len(actions)-1]
	}
	switch {
	case appeared && (last == ActAdded || last == ActRenamedNew || last == ActModified):
		return Replaced
	case renamedAway && last == ActRenamedOld:
		return Renamed
	case removed && last == ActRemoved:
		return Deleted
	case modified:
		return Modified
	case appeared:
		return Replaced
	}
	return ""
}

// Access is one audited file read from the Security log.
type Access struct {
	Object  string // full path of the file read
	Process string // full image path of the reader
	PID     uint32
	When    time.Time
}

// ParseAccesses decodes the JSON the Security-log query prints: one object
// or an array, with the process ID in hex ("0x1a2b").
func ParseAccesses(out []byte) ([]Access, error) {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return nil, nil
	}
	if strings.HasPrefix(s, "{") {
		s = "[" + s + "]"
	}
	var raw []struct{ Object, Proc, Pid, Time string }
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return nil, err
	}
	acc := make([]Access, 0, len(raw))
	for _, r := range raw {
		var pid uint64
		fmt.Sscanf(r.Pid, "0x%x", &pid)
		t, _ := time.Parse(time.RFC3339Nano, r.Time)
		acc = append(acc, Access{Object: r.Object, Process: r.Proc, PID: uint32(pid), When: t})
	}
	return acc, nil
}

// BaitReads picks the reads of bait files, minus Tripsilk itself and Windows
// scanners.
func BaitReads(acc []Access, reg *Registry, selfImage string) []Event {
	var evs []Event
	for _, a := range acc {
		if !reg.Has(a.Object) || (selfImage != "" && strings.EqualFold(a.Process, selfImage)) || IsSystemReader(a.Process) {
			continue
		}
		evs = append(evs, Event{Path: a.Object, Kind: Read, When: a.When, PID: a.PID, Process: a.Process})
	}
	return evs
}
