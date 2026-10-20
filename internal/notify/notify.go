// Package notify shows Windows toast notifications and manages Tripsilk's
// sign-in task.
package notify

import (
	"encoding/xml"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// TaskName is the scheduled task Tripsilk uses to start at sign-in. The startup
// watch ignores it.
const TaskName = "Tripsilk"

// LegacyTaskName is the sign-in task aWall, Tripsilk's earlier name, made.
// Turning start-at-sign-in on or off removes it.
const LegacyTaskName = "aWall"

// Limiter spaces out toasts so a burst of alerts doesn't spam the user. A
// suppressed toast is counted and mentioned in the next one.
type Limiter struct {
	mu         sync.Mutex
	gap        time.Duration
	last       time.Time
	suppressed int
}

func NewLimiter(gap time.Duration) *Limiter { return &Limiter{gap: gap} }

// Allow reports whether a toast may be shown now. If so, it returns how many
// were suppressed since the last one.
func (l *Limiter) Allow(now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() && now.Sub(l.last) < l.gap {
		l.suppressed++
		return false, 0
	}
	n := l.suppressed
	l.suppressed = 0
	l.last = now
	return true, n
}

// Clip shortens text for a toast line.
func Clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// TaskXML builds the Task Scheduler definition for starting Tripsilk at sign-in.
// schtasks' command-line defaults would stop Tripsilk on battery and kill it
// after 72 hours, silently ending protection; this definition turns both
// off. user is DOMAIN\\name; exe is Tripsilk's full path.
func TaskXML(user, exe string) string {
	x := func(s string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Starts Tripsilk when you sign in.</Description></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>` + x(user) + `</UserId></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + x(user) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>` + x(exe) + `</Command></Exec>
  </Actions>
</Task>
`
}

// UTF16LE encodes s with a byte order mark, the encoding schtasks /xml expects.
func UTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2+2*len(u))
	b[0], b[1] = 0xFF, 0xFE
	for i, c := range u {
		b[2+2*i] = byte(c)
		b[3+2*i] = byte(c >> 8)
	}
	return b
}
