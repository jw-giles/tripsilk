// Package shield is Tripsilk's ransomware shield. It watches the user's main
// folders for a burst of file changes far beyond normal use, then names the
// program that wrote the most data in that moment so it can be suspended.
// The decision logic here is pure and testable on any OS.
package shield

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Burst tracks distinct changed files in a sliding window.
type Burst struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	events    []event
	cooldown  time.Duration
	lastFire  time.Time
}

type event struct {
	path string
	at   time.Time
}

// NewBurst fires when at least threshold distinct files change within
// window, at most once per cooldown.
func NewBurst(window time.Duration, threshold int, cooldown time.Duration) *Burst {
	return &Burst{window: window, threshold: threshold, cooldown: cooldown}
}

// Observe records a change. It returns the number of distinct files changed
// in the window when that crosses the threshold, else 0.
func (b *Burst) Observe(path string, at time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, event{strings.ToLower(path), at})
	cut := at.Add(-b.window)
	i := 0
	for i < len(b.events) && b.events[i].at.Before(cut) {
		i++
	}
	b.events = b.events[i:]
	if len(b.events) < b.threshold {
		return 0
	}
	distinct := map[string]bool{}
	for _, e := range b.events {
		distinct[e.path] = true
	}
	n := len(distinct)
	if n < b.threshold || at.Sub(b.lastFire) < b.cooldown {
		return 0
	}
	b.lastFire = at
	b.events = nil
	return n
}

// Writer is one process's write volume between two samples.
type Writer struct {
	PID   uint32
	Image string
	Bytes uint64
}

// TopWriters ranks processes by bytes written between two counter samples,
// skipping excluded ones. A process absent from prev is measured from 0 only
// if isNew says it started after prev was taken; otherwise its lifetime
// total would masquerade as burst activity.
func TopWriters(prev, cur map[uint32]uint64, images map[uint32]string, isNew func(pid uint32) bool, exclude func(pid uint32, image string) bool) []Writer {
	var out []Writer
	for pid, now := range cur {
		before, known := prev[pid]
		if !known && (isNew == nil || !isNew(pid)) {
			continue
		}
		if now < before {
			continue // counter reset: PID reused by a new process
		}
		img := images[pid]
		if exclude != nil && exclude(pid, img) {
			continue
		}
		if d := now - before; d > 0 {
			out = append(out, Writer{PID: pid, Image: img, Bytes: d})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

// Trusted writers: Windows components and tools that legitimately touch
// many user files at once. Never suspended by the shield.
var trusted = map[string]bool{
	"system": true, "msmpeng.exe": true, "searchindexer.exe": true, "searchprotocolhost.exe": true,
	"explorer.exe": true, "svchost.exe": true, "onedrive.exe": true, "tiworker.exe": true,
	"trustedinstaller.exe": true, "mpdefendercoreservice.exe": true, "dllhost.exe": true,
	"runtimebroker.exe": true, "csrss.exe": true, "lsass.exe": true, "services.exe": true,
	"wininit.exe": true, "smss.exe": true, "registry": true, "memcompression": true,
}

// Trusted reports whether a program is on the built-in trusted list.
func Trusted(image string) bool {
	b := image
	if i := strings.LastIndexAny(b, `\/`); i >= 0 {
		b = b[i+1:]
	}
	return trusted[strings.ToLower(b)]
}

// MinSuspendBytes is the least a program must write during a burst before
// the shield will suspend it automatically.
const MinSuspendBytes = 1 << 20

// Confident reports whether the top writer clearly dominates: at least
// MinSuspendBytes and at least twice the next writer. Only then is an
// automatic suspend justified; otherwise the user picks from the candidates.
func Confident(ws []Writer) bool {
	if len(ws) == 0 || ws[0].Bytes < MinSuspendBytes {
		return false
	}
	return len(ws) == 1 || ws[0].Bytes >= 2*ws[1].Bytes
}
