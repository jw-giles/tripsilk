// Package eventlog copies Tripsilk's alerts into the Windows Event Log
// (Application log, source "Tripsilk"), for specialists whose tools already
// collect Windows events. Off by default. Standard library only.
package eventlog

import (
	"fmt"
	"strings"

	"tripsilk/internal/engine"
)

// Source is the event source name in the Application log.
const Source = "Tripsilk"

// IDs: one event ID per kind of alert, so a specialist can filter on it.
var IDs = map[string]uint32{
	"canary": 1001, "shield": 1002, "agent": 1003, "burst": 1004, "allowlist": 1005,
	"channel": 1006, "netmap": 1007, "rule": 1008, "defender": 1009, "system": 1010,
	"keys": 1011, "traffic": 1012,
}

// OtherID is used for any other kind of alert.
const OtherID = 1099

// Level is the Event Log level for a severity.
type Level int

const (
	Error       Level = 1
	Warning     Level = 2
	Information Level = 4
)

func LevelOf(s engine.Severity) Level {
	switch s {
	case engine.SevCritical:
		return Error
	case engine.SevHigh, engine.SevMedium:
		return Warning
	}
	return Information
}

func IDOf(source string) uint32 {
	if id, ok := IDs[source]; ok {
		return id
	}
	return OtherID
}

// maxText keeps an event under the Event Log's 32K-character limit.
const maxText = 30000

// Text is the event's message: the plain version first, then the detail
// and evidence, one field per line so it greps well.
func Text(a engine.Alert) string {
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString(a.Title + "\r\n\r\n")
	if a.Summary != "" {
		b.WriteString(a.Summary + " " + a.Why + "\r\n\r\n")
	}
	b.WriteString(a.Detail + "\r\n\r\n")
	line("Severity", string(a.Severity))
	line("Kind", a.Source)
	line("Program", a.Process)
	if a.PID != 0 {
		line("PID", fmt.Sprint(a.PID))
	}
	line("Started program", a.Child)
	line("Place", a.Dest)
	line("Channel", a.Channel)
	line("AI service", a.Service)
	if e := a.Evidence; e != nil {
		line("SHA-256", e.SHA256)
		line("Hash note", e.HashNote)
		for i, l := range e.Chain {
			line(fmt.Sprintf("Parent %d", i), fmt.Sprintf("%s (PID %d)", l.Image, l.PID))
		}
		line("Destination", e.Destination)
	}
	line("Alert ID", a.ID)
	line("Time", a.Time.UTC().Format("2006-01-02T15:04:05.000Z"))
	s := b.String()
	if len(s) > maxText {
		s = s[:maxText] + "\r\n(cut short)"
	}
	return s
}
