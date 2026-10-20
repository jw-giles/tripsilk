// Package sysmon reads Microsoft Sysmon's event log when Sysmon is
// installed. Tripsilk doesn't install or configure Sysmon; when a
// specialist already runs it, its events go into Tripsilk's journal beside
// Tripsilk's own, and the SHA-256 Sysmon took when a program started is
// used as evidence (a hash taken at launch, before the file could be
// swapped). Standard library only.
package sysmon

import (
	"encoding/xml"
	"strconv"
	"strings"
	"time"
)

// Channel is Sysmon's event log.
const Channel = "Microsoft-Windows-Sysmon/Operational"

// Event is one Sysmon event, reduced to what Tripsilk uses. Fields hold
// Sysmon's own names and values, so a specialist sees them as Sysmon
// reported.
type Event struct {
	ID       int               `json:"id"` // 1 process create, 3 network connect, 22 DNS query, ...
	RecordID uint64            `json:"recordId"`
	Time     time.Time         `json:"time"`
	PID      uint32            `json:"pid,omitempty"`
	Image    string            `json:"image,omitempty"`
	SHA256   string            `json:"sha256,omitempty"` // from Hashes, when Sysmon's config includes SHA256
	Fields   map[string]string `json:"fields"`
}

// Kept: the fields journaled for each event ID. Others (Sysmon has dozens)
// are left out to keep the journal small.
var kept = map[int][]string{
	1:  {"Image", "CommandLine", "ProcessId", "ParentProcessId", "ParentImage", "ParentCommandLine", "User", "Hashes", "IntegrityLevel"},
	3:  {"Image", "ProcessId", "Protocol", "DestinationIp", "DestinationHostname", "DestinationPort", "User"},
	22: {"Image", "ProcessId", "QueryName", "QueryResults", "QueryStatus"},
}

type xmlEvent struct {
	System struct {
		EventID       int    `xml:"EventID"`
		EventRecordID uint64 `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// Parse reads one event as Windows renders it (EvtRender XML). Events with
// IDs Tripsilk doesn't use come back with ok false.
func Parse(raw string) (Event, bool) {
	var x xmlEvent
	if err := xml.Unmarshal([]byte(raw), &x); err != nil {
		return Event{}, false
	}
	want, ok := kept[x.System.EventID]
	if !ok {
		return Event{}, false
	}
	all := make(map[string]string, len(x.Data))
	for _, d := range x.Data {
		all[d.Name] = strings.TrimSpace(d.Value)
	}
	ev := Event{ID: x.System.EventID, RecordID: x.System.EventRecordID, Fields: map[string]string{}}
	ev.Time, _ = time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime)
	for _, k := range want {
		if v := all[k]; v != "" {
			ev.Fields[k] = v
		}
	}
	ev.Image = all["Image"]
	if p, err := strconv.ParseUint(all["ProcessId"], 10, 32); err == nil {
		ev.PID = uint32(p)
	}
	ev.SHA256 = HashFrom(all["Hashes"])
	return ev, true
}

// HashFrom picks SHA256 out of Sysmon's Hashes field
// ("SHA1=...,MD5=...,SHA256=...,IMPHASH=...").
func HashFrom(hashes string) string {
	for _, part := range strings.Split(hashes, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(k, "SHA256") && len(v) == 64 {
			return strings.ToLower(v)
		}
	}
	return ""
}

// Hashes remembers the launch hash of recent processes, by PID and image,
// so an alert about a running program can show the hash Sysmon took when
// it started. Not safe for concurrent use; the caller locks.
type Hashes struct {
	m     map[uint32]hashEntry
	order []uint32
	max   int
}

type hashEntry struct {
	image, sum string
}

func NewHashes(max int) *Hashes { return &Hashes{m: map[uint32]hashEntry{}, max: max} }

func (h *Hashes) Add(pid uint32, image, sum string) {
	if pid == 0 || sum == "" {
		return
	}
	if _, ok := h.m[pid]; !ok {
		h.order = append(h.order, pid)
	}
	h.m[pid] = hashEntry{image: image, sum: sum}
	for len(h.order) > h.max {
		delete(h.m, h.order[0])
		h.order = h.order[1:]
	}
}

// Get returns the launch hash for pid if it was recorded for the same
// program (a reused PID with another image doesn't match).
func (h *Hashes) Get(pid uint32, image string) (string, bool) {
	e, ok := h.m[pid]
	if !ok || !strings.EqualFold(e.image, image) {
		return "", false
	}
	return e.sum, true
}
