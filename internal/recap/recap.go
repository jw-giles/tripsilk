// Package recap builds the weekly summary on Home from Tripsilk's event
// journal: what was recorded, what alerted, what was stopped. It reads the
// journal files directly and parses only alert lines in full, so a week of
// events (up to the journal's 256 MB) is summed in seconds. Standard
// library only.
package recap

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"

	"tripsilk/internal/engine"
)

// Item is one line of a list in the recap.
type Item struct {
	Title string    `json:"title"`
	Count int       `json:"count"`
	Last  time.Time `json:"last"`
}

// Recap is a week (or less, on a new install) in numbers.
type Recap struct {
	From     time.Time      `json:"from"` // the oldest event read, or the window start
	To       time.Time      `json:"to"`
	Events   int            `json:"events"`  // everything the sensor recorded
	Starts   int            `json:"starts"`  // program starts
	Alerts   map[string]int `json:"alerts"`  // by severity
	Top      []Item         `json:"top"`     // most frequent alerts, grouped by title
	Stopped  []Item         `json:"stopped"` // freezes and suspends Tripsilk did itself
	Practice int            `json:"practice"`
	AIApps   []string       `json:"aiApps"`            // programs that alerted as AI apps
	Partial  bool           `json:"partial,omitempty"` // a file couldn't be read
}

var (
	alertTag = []byte(`"type":"alert"`)
	startTag = []byte(`"type":"proc_start"`)
	timeHead = []byte(`{"time":"`)
)

// lineTime reads the time at the start of a journal line without parsing
// the rest (records are written with "time" first).
func lineTime(b []byte) (time.Time, bool) {
	if !bytes.HasPrefix(b, timeHead) {
		return time.Time{}, false
	}
	rest := b[len(timeHead):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, string(rest[:end]))
	return t, err == nil
}

// stopped reports whether an alert says Tripsilk froze or suspended
// something itself (not in practice).
func stopped(a engine.Alert) bool {
	return strings.Contains(a.Detail, "Tripsilk froze ") || strings.Contains(a.Detail, "Tripsilk suspended it")
}

func practice(a engine.Alert) bool {
	return strings.Contains(a.Detail, "Practice: with automatic containment on")
}

// aiSources alert about a program because it's an AI app or one of its
// programs; Process is then the AI app.
var aiSources = map[string]bool{"netmap": true, "agent": true, "burst": true, "allowlist": true, "rule": true}

// Build sums journal files in dir from since to now.
func Build(dir string, files []string, since, now time.Time) Recap {
	r := Recap{From: now, To: now, Alerts: map[string]int{}}
	top, stop := map[string]*Item{}, map[string]*Item{}
	apps := map[string]string{}
	for _, name := range files {
		if fi, err := os.Stat(name); err != nil || fi.ModTime().Before(since) {
			continue // written to last before the window
		}
		f, err := os.Open(name)
		if err != nil {
			r.Partial = true
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			b := sc.Bytes()
			t, ok := lineTime(b)
			if !ok || t.Before(since) || t.After(now) {
				continue
			}
			r.Events++
			if t.Before(r.From) {
				r.From = t
			}
			if bytes.Contains(b, startTag) {
				r.Starts++
				continue
			}
			if !bytes.Contains(b, alertTag) {
				continue
			}
			var rec struct {
				Type string       `json:"type"`
				Data engine.Alert `json:"data"`
			}
			if json.Unmarshal(b, &rec) != nil || rec.Type != "alert" {
				continue
			}
			a := rec.Data
			if a.Severity == engine.SevInfo {
				continue // Tripsilk's own notes ("Rule removed")
			}
			r.Alerts[string(a.Severity)]++
			add(top, a.Title, t)
			if stopped(a) {
				add(stop, a.Title, t)
			}
			if practice(a) {
				r.Practice++
			}
			if aiSources[a.Source] && a.Process != "" {
				apps[strings.ToLower(a.Process)] = a.Process
			}
		}
		if sc.Err() != nil {
			r.Partial = true
		}
		f.Close()
	}
	if r.From.After(since) && r.Events == 0 {
		r.From = since
	}
	r.Top = sorted(top, 5)
	r.Stopped = sorted(stop, 10)
	for _, img := range apps {
		r.AIApps = append(r.AIApps, img)
	}
	sort.Slice(r.AIApps, func(i, j int) bool { return strings.ToLower(r.AIApps[i]) < strings.ToLower(r.AIApps[j]) })
	return r
}

func add(m map[string]*Item, title string, t time.Time) {
	it := m[title]
	if it == nil {
		it = &Item{Title: title}
		m[title] = it
	}
	it.Count++
	if t.After(it.Last) {
		it.Last = t
	}
}

func sorted(m map[string]*Item, n int) []Item {
	out := make([]Item, 0, len(m))
	for _, it := range m {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Last.After(out[j].Last)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
