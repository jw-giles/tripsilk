//go:build windows && (amd64 || arm64)

// 64-bit only: trace handles and keywords are 64-bit values passed in one
// register each, which 32-bit Windows splits across two.

package sensor

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"tripsilk/internal/win"
)

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procStartTraceW    = advapi32.NewProc("StartTraceW")
	procControlTraceW  = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = advapi32.NewProc("OpenTraceW")
	procProcessTrace   = advapi32.NewProc("ProcessTrace")
	procCloseTrace     = advapi32.NewProc("CloseTrace")
)

const (
	wnodeFlagTracedGUID     = 0x00020000
	eventTraceRealTimeMode  = 0x00000100
	eventTraceUseMsFlush    = 0x00000010
	eventTraceControlStop   = 1
	eventControlEnable      = 1
	traceLevelVerbose       = 5
	processTraceRealTime    = 0x00000100
	processTraceEventRecord = 0x10000000
	eventFilterTypeEventID  = 0x80000200
	errAlreadyExists        = 183
	errCancelled            = 1223
	invalidProcessTrace     = ^uint64(0)
	clientContextSystemTime = 2 // event timestamps as FILETIME
)

// Layouts below are the x64 Windows SDK structures. Sizes are checked in
// layout_windows_test.go.

type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              GUID
	ClientContext     uint32
	Flags             uint32
}

type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// propsBuf is EVENT_TRACE_PROPERTIES with room after it for the session
// name, which Windows writes back on some calls.
type propsBuf struct {
	p     eventTraceProperties
	names [1024]uint16
}

func newProps() *propsBuf {
	b := &propsBuf{}
	b.p.Wnode.BufferSize = uint32(unsafe.Sizeof(*b))
	b.p.Wnode.Flags = wnodeFlagTracedGUID
	b.p.Wnode.ClientContext = clientContextSystemTime
	b.p.LoggerNameOffset = uint32(unsafe.Sizeof(b.p))
	return b
}

type eventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      GUID
	EventDescriptor eventDescriptor
	ProcessorTime   uint64
	ActivityID      GUID
}

type eventRecord struct {
	Header            eventHeader
	BufferContext     uint32
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          unsafe.Pointer
	UserContext       uintptr
}

// eventTraceLogfile is EVENT_TRACE_LOGFILEW. Only the fields Tripsilk sets
// or reads are named; the rest is padding of the right size.
type eventTraceLogfile struct {
	LogFileName      *uint16
	LoggerName       *uint16
	CurrentTime      int64
	BuffersRead      uint32
	ProcessTraceMode uint32
	CurrentEvent     [88]byte  // EVENT_TRACE
	LogfileHeader    [280]byte // TRACE_LOGFILE_HEADER
	BufferCallback   uintptr
	BufferSize       uint32
	Filled           uint32
	EventsLost       uint32
	_                uint32
	EventCallback    uintptr
	IsKernelTrace    uint32
	_                uint32
	Context          uintptr
}

type eventFilterDescriptor struct {
	Ptr  uint64
	Size uint32
	Type uint32
}

type enableTraceParameters struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceID         GUID
	EnableFilterDesc *eventFilterDescriptor
	FilterDescCount  uint32
}

// Sensor is one real-time tracing session.
type Sensor struct {
	name    string
	out     chan Event
	handler func(Event)

	session  uint64
	consumer uint64
	props    *propsBuf
	lf       *eventTraceLogfile // kept for the session's lifetime
	nameW    *uint16
	closed   atomic.Bool

	running  atomic.Bool
	events   atomic.Uint64
	dropped  atomic.Uint64
	filtered bool
	flushMs  int
	errMu    sync.Mutex
	err      string
	done     chan struct{}
}

// current is the sensor the ETW callback delivers to. Windows calls the
// callback with no context argument Tripsilk can use, and only one sensor
// runs per process.
var (
	current   atomic.Pointer[Sensor]
	callbacks = syscall.NewCallback(onEvent)
	startMu   sync.Mutex
)

// New prepares a sensor with a fixed session name. A fixed name means a
// session left behind by a crash is found and replaced on the next start,
// so Windows never runs out of tracing sessions.
func New(name string) *Sensor {
	return &Sensor{name: name, out: make(chan Event, 8192), done: make(chan struct{})}
}

// Start begins tracing and calls fn for each event on its own goroutine.
// Needs administrator. On error nothing is left running.
func (s *Sensor) Start(fn func(Event)) error {
	startMu.Lock()
	defer startMu.Unlock()
	if current.Load() != nil {
		return errors.New("a sensor is already running in this process")
	}
	s.handler = fn
	name, err := syscall.UTF16PtrFromString(s.name)
	if err != nil {
		return err
	}
	// A leftover session from a crash: stop it first.
	stopSession(name)

	if err := s.startSession(name, true); err != nil {
		// Older Windows rejects millisecond flushing; fall back to 1 second.
		if err2 := s.startSession(name, false); err2 != nil {
			return fmt.Errorf("start tracing session: %v", err)
		}
	}
	ok := false
	defer func() {
		if !ok {
			stopSession(name)
		}
	}()

	s.filtered = true
	for _, p := range []struct {
		guid    GUID
		keyword uint64
		ids     []uint16
		what    string
	}{
		{KernelProcess, 0x10, processIDs, "process"},  // WINEVENT_KEYWORD_PROCESS
		{KernelNetwork, 0x30, networkIDs, "network"},  // KEYWORD_IPV4 | KEYWORD_IPV6
		{DNSClient, ^uint64(0), dnsIDs, "DNS lookup"}, // every keyword; filtered to 3008
	} {
		filtered, err := s.enable(p.guid, p.keyword, p.ids)
		if err != nil {
			return fmt.Errorf("enable %s events: %v", p.what, err)
		}
		if !filtered {
			s.filtered = false
		}
	}

	s.nameW = name
	s.lf = &eventTraceLogfile{
		LoggerName:       name,
		ProcessTraceMode: processTraceRealTime | processTraceEventRecord,
		EventCallback:    callbacks,
	}
	r, _, e := procOpenTraceW.Call(uintptr(unsafe.Pointer(s.lf)))
	if uint64(r) == invalidProcessTrace {
		return fmt.Errorf("open tracing session: %v", e)
	}
	s.consumer = uint64(r)
	current.Store(s)
	s.running.Store(true)
	ok = true

	go s.dispatch()
	go s.process()
	return nil
}

func (s *Sensor) startSession(name *uint16, msFlush bool) error {
	p := newProps()
	p.p.LogFileMode = eventTraceRealTimeMode
	p.p.BufferSize = 64 // KB
	p.p.MinimumBuffers = 4
	p.p.MaximumBuffers = 64
	if msFlush {
		p.p.LogFileMode |= eventTraceUseMsFlush
		p.p.FlushTimer = 100 // ms
		s.flushMs = 100
	} else {
		p.p.FlushTimer = 1 // s
		s.flushMs = 1000
	}
	var h uint64
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(p)))
	if r != 0 {
		return syscall.Errno(r)
	}
	s.session, s.props = h, p
	return nil
}

// enable turns a provider on, asking Windows to deliver only ids. If
// Windows refuses the filter, the provider is enabled unfiltered and the
// callback drops the extra events itself (more work, same result).
func (s *Sensor) enable(guid GUID, keyword uint64, ids []uint16) (filtered bool, err error) {
	filter := eventIDFilter(ids)
	desc := eventFilterDescriptor{Ptr: uint64(uintptr(unsafe.Pointer(&filter[0]))), Size: uint32(len(filter)), Type: eventFilterTypeEventID}
	params := enableTraceParameters{Version: 2, EnableFilterDesc: &desc, FilterDescCount: 1}
	r, _, _ := procEnableTraceEx2.Call(uintptr(s.session), uintptr(unsafe.Pointer(&guid)), eventControlEnable,
		traceLevelVerbose, uintptr(keyword), 0, 0, uintptr(unsafe.Pointer(&params)))
	runtime.KeepAlive(filter)
	runtime.KeepAlive(&desc)
	if r == 0 {
		return true, nil
	}
	r, _, _ = procEnableTraceEx2.Call(uintptr(s.session), uintptr(unsafe.Pointer(&guid)), eventControlEnable,
		traceLevelVerbose, uintptr(keyword), 0, 0, 0)
	if r != 0 {
		return false, syscall.Errno(r)
	}
	return false, nil
}

// process runs ProcessTrace, which blocks and calls onEvent on this thread
// until the session is closed.
func (s *Sensor) process() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	h := s.consumer
	r, _, _ := procProcessTrace.Call(uintptr(unsafe.Pointer(&h)), 1, 0, 0)
	if s.running.Load() && r != 0 && r != errCancelled {
		s.setErr(fmt.Sprintf("event tracing stopped: %v", syscall.Errno(r)))
	}
	s.running.Store(false)
	s.closeConsumer()
	current.CompareAndSwap(s, nil)
	close(s.out)
}

func (s *Sensor) dispatch() {
	defer close(s.done)
	for ev := range s.out {
		func() {
			defer func() { _ = recover() }() // a handler bug must not stop the sensor
			s.handler(ev)
		}()
	}
}

// Stop ends the session and waits for queued events to be handled.
func (s *Sensor) Stop() {
	if !s.running.Swap(false) {
		return
	}
	name, _ := syscall.UTF16PtrFromString(s.name)
	stopSession(name)
	s.closeConsumer()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
	}
}

// closeConsumer releases the consumer handle once, whichever of Stop or the
// end of ProcessTrace gets there first.
func (s *Sensor) closeConsumer() {
	if !s.closed.Swap(true) {
		procCloseTrace.Call(uintptr(s.consumer))
	}
}

// Running reports whether events are flowing.
func (s *Sensor) Running() bool { return s.running.Load() }

func (s *Sensor) Stats() Stats {
	st := Stats{Running: s.running.Load(), Events: s.events.Load(), Dropped: s.dropped.Load(),
		Filtered: s.filtered, FlushMs: s.flushMs}
	s.errMu.Lock()
	st.Error = s.err
	s.errMu.Unlock()
	if s.running.Load() {
		p := newProps()
		name, _ := syscall.UTF16PtrFromString(s.name)
		const eventTraceControlQuery = 0
		if r, _, _ := procControlTraceW.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(p)), eventTraceControlQuery); r == 0 {
			st.Lost = p.p.EventsLost + p.p.RealTimeBuffersLost
		}
	}
	return st
}

func (s *Sensor) setErr(e string) {
	s.errMu.Lock()
	s.err = e
	s.errMu.Unlock()
}

// StopSession ends a tracing session by name, whichever process started
// it. The uninstaller uses it so a session left by a killed Tripsilk
// doesn't outlive the program. Stopping a session that isn't running is
// harmless.
func StopSession(name string) {
	if p, err := syscall.UTF16PtrFromString(name); err == nil {
		stopSession(p)
	}
}

func stopSession(name *uint16) {
	p := newProps()
	procControlTraceW.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(p)), eventTraceControlStop)
}

// onEvent is the ETW callback. It runs on the ProcessTrace thread, so it does
// as little as possible: parse, read a new process's details while it still
// exists, and queue.
func onEvent(r *eventRecord) uintptr {
	defer func() { _ = recover() }()
	s := current.Load()
	if s == nil || r == nil {
		return 0
	}
	h := &r.Header
	var data []byte
	if r.UserData != nil && r.UserDataLength > 0 {
		data = unsafe.Slice((*byte)(r.UserData), int(r.UserDataLength))
	}
	ev := Event{Time: filetime(uint64(h.TimeStamp)), Seen: time.Now()}
	// The session asks for system-time stamps; if Windows used another
	// clock, fall back to the arrival time so time checks still work.
	if ev.Time.Year() < 2001 || ev.Time.After(ev.Seen.Add(time.Hour)) {
		ev.Time = ev.Seen
	}
	id := h.EventDescriptor.ID
	if hook := RawHook; hook != nil {
		prov := map[GUID]string{KernelProcess: "process", KernelNetwork: "network", DNSClient: "dns"}[h.ProviderID]
		hook(Raw{Provider: prov, ID: id, Version: h.EventDescriptor.Version, PID: h.ProcessID,
			Time: ev.Time, Data: append([]byte(nil), data...)})
	}
	switch h.ProviderID {
	case KernelProcess:
		switch id {
		case idProcStart:
			pid, ppid, created, nt, ok := parseProcStart(data, ev.Time)
			if !ok {
				return 0
			}
			ev.Kind, ev.PID, ev.PPID, ev.Created = ProcStart, pid, ppid, created
			// Read the process live now, while it exists: the kernel's own
			// answers don't depend on the payload layout, and a short-lived
			// program may be gone by the time anything else looks. A live
			// process created long before this event is a reused PID.
			img, c := win.ProcessInfo(pid)
			if img != "" && plausible(c, ev.Time, 5*time.Second) {
				ev.Image, ev.Created = img, c
				if pp, ok := win.ParentPID(pid); ok {
					ev.PPID = pp
				}
				ev.CmdLine = win.CommandLine(pid)
			} else if nt != "" {
				ev.Image = dosPath(nt)
			}
		case idProcStop:
			pid, created, ok := parseProcStop(data, ev.Time)
			if !ok {
				return 0
			}
			ev.Kind, ev.PID, ev.Created = ProcStop, pid, created
		default:
			return 0
		}
	case KernelNetwork:
		var v6 bool
		switch id {
		case idTCP4Connect, idTCP4Accept:
		case idTCP6Connect, idTCP6Accept:
			v6 = true
		default:
			return 0
		}
		pid, local, remote, ok := parseTCP(v6, data)
		if !ok {
			return 0
		}
		ev.Kind, ev.PID, ev.Local, ev.Remote = Connect, pid, local, remote
		if id == idTCP4Accept || id == idTCP6Accept {
			ev.Kind = Accept
		}
	case DNSClient:
		if id != idDNSQueryDone {
			return 0
		}
		name, status, answers, ok := parseDNS(data)
		if !ok || name == "" {
			return 0
		}
		ev.Kind, ev.PID, ev.Name, ev.Status, ev.Answers = DNS, h.ProcessID, name, status, answers
	default:
		return 0
	}
	s.events.Add(1)
	select {
	case s.out <- ev:
	default:
		s.dropped.Add(1)
	}
	return 0
}

// ---- Kernel paths to drive letters ----

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procQueryDosDeviceW = kernel32.NewProc("QueryDosDeviceW")
	devMu               sync.Mutex
	devMap              map[string]string // "\device\harddiskvolume3" -> "C:"
	devMapAt            time.Time
)

// dosPath turns \Device\HarddiskVolume3\Windows\x.exe into C:\Windows\x.exe.
// Unknown devices are returned as given.
func dosPath(nt string) string {
	devMu.Lock()
	if devMap == nil || time.Since(devMapAt) > 5*time.Minute {
		devMap, devMapAt = readDevices(), time.Now()
	}
	m := devMap
	devMu.Unlock()
	low := strings.ToLower(nt)
	for dev, drive := range m {
		if strings.HasPrefix(low, dev+`\`) {
			return drive + nt[len(dev):]
		}
	}
	return nt
}

func readDevices() map[string]string {
	m := map[string]string{}
	buf := make([]uint16, 1024)
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		d, _ := syscall.UTF16PtrFromString(drive)
		n, _, _ := procQueryDosDeviceW.Call(uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n == 0 {
			continue
		}
		target := syscall.UTF16ToString(buf[:n])
		if target != "" {
			m[strings.ToLower(target)] = drive
		}
	}
	return m
}
