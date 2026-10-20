// Package sensor reads Windows' built-in event tracing (ETW) in real time:
// process starts and exits, outgoing and accepted TCP connections, and DNS
// lookups with the process that made them. No driver is involved; these are
// the same providers Windows' own tools read.
//
// Polling (every 2 to 5 seconds) misses a program that starts and exits
// between two looks. The sensor sees every start as it happens, typically
// within a few hundred milliseconds, and the rest of Tripsilk falls back to
// polling whenever the sensor isn't running.
//
// Payload parsing lives in this file, separate from the Windows calls, so it
// can be tested on any OS with captured or synthetic payloads.
package sensor

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"time"
	"unicode/utf16"
)

// Kind is what an event describes.
type Kind string

const (
	ProcStart Kind = "proc_start"
	ProcStop  Kind = "proc_stop"
	Connect   Kind = "tcp_connect"
	Accept    Kind = "tcp_accept"
	DNS       Kind = "dns"
)

// Event is one observation. Fields not relevant to a Kind are left zero.
type Event struct {
	Kind Kind      `json:"kind"`
	Time time.Time `json:"time"` // when Windows recorded it
	Seen time.Time `json:"seen"` // when Tripsilk received it
	PID  uint32    `json:"pid"`

	// Process starts and exits.
	PPID    uint32    `json:"ppid,omitempty"`
	Created time.Time `json:"created,omitempty"`
	Image   string    `json:"image,omitempty"`   // full path when known
	CmdLine string    `json:"cmdline,omitempty"` // read at start; empty if it exited first

	// Connections.
	Local  netip.AddrPort `json:"local,omitempty"`
	Remote netip.AddrPort `json:"remote,omitempty"`

	// DNS lookups.
	Name    string       `json:"name,omitempty"`
	Answers []netip.Addr `json:"answers,omitempty"`
	Status  uint32       `json:"status,omitempty"` // 0 = success
}

// Raw is one event exactly as Windows delivered it, for recording test
// fixtures (tripsilk-selftest -record). Data is a copy.
type Raw struct {
	Provider string    `json:"provider"` // "process", "network", "dns"
	ID       uint16    `json:"id"`
	Version  uint8     `json:"version"`
	PID      uint32    `json:"headerPid"`
	Time     time.Time `json:"time"`
	Data     []byte    `json:"data"`
}

// RawHook, when set, receives every event the sensor reads before it is
// parsed. Only the self-test sets it.
var RawHook func(Raw)

// Stats describes the sensor's health, for the dashboard and self-test.
type Stats struct {
	Running  bool   `json:"running"`
	Error    string `json:"error,omitempty"`
	Events   uint64 `json:"events"`
	Dropped  uint64 `json:"dropped"`  // queue full: Tripsilk fell behind
	Lost     uint32 `json:"lost"`     // Windows reported lost events
	Filtered bool   `json:"filtered"` // Windows filters events by ID for us (cheaper)
	FlushMs  int    `json:"flushMs"`  // how often Windows hands events over
}

// GUID is a Windows GUID in memory layout.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// Provider GUIDs (from each provider's manifest; `logman query providers`
// lists them on any Windows 10/11 PC).
var (
	KernelProcess = GUID{0x22FB2CD6, 0x0E7B, 0x422B, [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}}
	KernelNetwork = GUID{0x7DD42A49, 0x5329, 0x4832, [8]byte{0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}}
	DNSClient     = GUID{0x1C95126E, 0x7EEA, 0x49A9, [8]byte{0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D}}
)

// Event IDs Tripsilk asks each provider for.
const (
	idProcStart = 1
	idProcStop  = 2

	idTCP4Connect = 12
	idTCP4Accept  = 15
	idTCP6Connect = 28
	idTCP6Accept  = 31

	idDNSQueryDone = 3008
)

var (
	processIDs = []uint16{idProcStart, idProcStop}
	networkIDs = []uint16{idTCP4Connect, idTCP4Accept, idTCP6Connect, idTCP6Accept}
	dnsIDs     = []uint16{idDNSQueryDone}
)

// filetime converts a Windows FILETIME (100 ns ticks since 1601) to time.
// It matches syscall.Filetime.Nanoseconds, which the polling code uses, so a
// process seen both ways has the same creation time.
func filetime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000 // 1601 to 1970 in 100 ns ticks
	return time.Unix(0, (int64(ft)-epochDiff)*100)
}

// utf16z reads a NUL-terminated UTF-16LE string from b and returns it and
// the bytes after the terminator. ok is false if no terminator is found.
func utf16z(b []byte) (s string, rest []byte, ok bool) {
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			u := make([]uint16, i/2)
			for j := range u {
				u[j] = binary.LittleEndian.Uint16(b[2*j:])
			}
			return string(utf16.Decode(u)), b[i+2:], true
		}
	}
	return "", nil, false
}

// procLayout is one known arrangement of Kernel-Process start/stop payloads.
// Versions 0 to 2 start ProcessID, CreateTime, ParentProcessID, SessionID
// (version 1 and later add Flags). Version 3 (recent Windows 10 and 11)
// puts a 64-bit sequence number after each process ID and adds token
// fields and a SID before ImageName.
type procLayout struct {
	created, ppid int
	images        func(b []byte) []int // candidate offsets of ImageName
}

var startLayouts = []procLayout{
	{created: 12, ppid: 20, images: func(b []byte) []int { return []int{sidEnd(b, 48)} }}, // v3+
	{created: 4, ppid: 12, images: func(b []byte) []int { return []int{24, 20} }},         // v1, v2, then v0
}

// sidEnd returns the offset just past a SID starting at off, or -1.
func sidEnd(b []byte, off int) int {
	if off+8 > len(b) || b[off] != 1 { // SID revision is always 1
		return -1
	}
	n := int(b[off+1])
	end := off + 8 + 4*n
	if n > 15 || end > len(b) {
		return -1
	}
	return end
}

// plausible reports whether a creation time read from a payload fits the
// event's own timestamp. A process start is logged as the process is
// created; a wrong layout yields 1601 or a far-off date.
func plausible(created, eventTime time.Time, slack time.Duration) bool {
	if created.IsZero() || eventTime.IsZero() {
		return false
	}
	d := eventTime.Sub(created)
	return d > -5*time.Second && d < slack
}

// parseProcStart reads Kernel-Process event 1, choosing the layout whose
// creation time agrees with the event's timestamp. Callers prefer live
// process details when the process still exists; this is the fallback for
// programs that exited first. The image name is a kernel path
// (\Device\HarddiskVolume3\...), converted by the caller.
func parseProcStart(b []byte, eventTime time.Time) (pid, ppid uint32, created time.Time, ntImage string, ok bool) {
	if len(b) < 4 {
		return 0, 0, time.Time{}, "", false
	}
	pid = binary.LittleEndian.Uint32(b[0:])
	for _, l := range startLayouts {
		if l.ppid+4 > len(b) {
			continue
		}
		c := filetime(binary.LittleEndian.Uint64(b[l.created:]))
		if !plausible(c, eventTime, 5*time.Second) {
			continue
		}
		created, ppid = c, binary.LittleEndian.Uint32(b[l.ppid:])
		for _, off := range l.images(b) {
			if off >= 0 && off < len(b) {
				if s, _, found := utf16z(b[off:]); found && strings.HasPrefix(s, `\`) {
					ntImage = s
					break
				}
			}
		}
		return pid, ppid, created, ntImage, true
	}
	return pid, 0, time.Time{}, "", true // PID only: still worth recording
}

// parseProcStop reads Kernel-Process event 2: ProcessID, then (version 2+)
// a sequence number, then CreateTime. The creation time is only used to
// avoid removing a newer process that reused the PID, so a layout that
// can't be confirmed returns a zero time.
func parseProcStop(b []byte, eventTime time.Time) (pid uint32, created time.Time, ok bool) {
	if len(b) < 4 {
		return 0, time.Time{}, false
	}
	pid = binary.LittleEndian.Uint32(b[0:])
	for _, off := range []int{4, 12} { // a sequence number at 4 is never a plausible time
		if off+8 <= len(b) {
			if c := filetime(binary.LittleEndian.Uint64(b[off:])); plausible(c, eventTime, 100*365*24*time.Hour) {
				return pid, c, true
			}
		}
	}
	return pid, time.Time{}, true
}

// parseTCP reads Kernel-Network connect/accept events. Layout: PID, size,
// daddr, saddr, dport, sport, ... Addresses are raw (network order) and
// ports big-endian, as in the classic kernel TcpIp events.
func parseTCP(v6 bool, b []byte) (pid uint32, local, remote netip.AddrPort, ok bool) {
	alen := 4
	if v6 {
		alen = 16
	}
	need := 8 + 2*alen + 4
	if len(b) < need {
		return 0, local, remote, false
	}
	pid = binary.LittleEndian.Uint32(b[0:])
	daddr, _ := netip.AddrFromSlice(b[8 : 8+alen])
	saddr, _ := netip.AddrFromSlice(b[8+alen : 8+2*alen])
	p := 8 + 2*alen
	dport := binary.BigEndian.Uint16(b[p:])
	sport := binary.BigEndian.Uint16(b[p+2:])
	return pid, netip.AddrPortFrom(saddr.Unmap(), sport), netip.AddrPortFrom(daddr.Unmap(), dport), true
}

// parseDNS reads DNS-Client event 3008 (query completed): QueryName,
// QueryType, QueryOptions, QueryStatus, QueryResults.
func parseDNS(b []byte) (name string, status uint32, answers []netip.Addr, ok bool) {
	name, rest, found := utf16z(b)
	if !found || len(rest) < 16 {
		return "", 0, nil, false
	}
	status = binary.LittleEndian.Uint32(rest[12:])
	results, _, _ := utf16z(rest[16:])
	return strings.TrimSuffix(strings.ToLower(name), "."), status, parseAnswers(results), true
}

// parseAnswers reads QueryResults, e.g. "::ffff:1.2.3.4;2606:4700::1;" or
// "type:  5 edge.example.net;1.2.3.4;". CNAME entries are skipped.
func parseAnswers(s string) []netip.Addr {
	var out []netip.Addr
	for _, tok := range strings.Split(s, ";") {
		tok = strings.TrimSpace(tok)
		if tok == "" || strings.HasPrefix(tok, "type:") {
			continue
		}
		if a, err := netip.ParseAddr(tok); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// eventIDFilter builds an EVENT_FILTER_EVENT_ID: FilterIn, Reserved, Count,
// then the IDs, so Windows only delivers the events Tripsilk reads.
func eventIDFilter(ids []uint16) []byte {
	b := make([]byte, 4+2*len(ids))
	b[0] = 1 // FilterIn: deliver only these
	binary.LittleEndian.PutUint16(b[2:], uint16(len(ids)))
	for i, id := range ids {
		binary.LittleEndian.PutUint16(b[4+2*i:], id)
	}
	return b
}
