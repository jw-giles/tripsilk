//go:build windows

package sysmon

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	wevtapi       = syscall.NewLazyDLL("wevtapi.dll")
	procEvtQuery  = wevtapi.NewProc("EvtQuery")
	procEvtNext   = wevtapi.NewProc("EvtNext")
	procEvtRender = wevtapi.NewProc("EvtRender")
	procEvtClose  = wevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1
	errNoMoreItems           = syscall.Errno(259)
	errInsufficientBuffer    = syscall.Errno(122)
	errChannelNotFound       = syscall.Errno(15007)
	errNotFound              = syscall.Errno(1168)
)

// ErrNotInstalled: Sysmon's log doesn't exist on this PC.
var ErrNotInstalled = errors.New("Sysmon isn't installed")

func query(xpath string, flags uintptr) (uintptr, error) {
	ch, _ := syscall.UTF16PtrFromString(Channel)
	q, _ := syscall.UTF16PtrFromString(xpath)
	h, _, err := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)), evtQueryChannelPath|flags)
	if h == 0 {
		if errors.Is(err, errChannelNotFound) || errors.Is(err, errNotFound) {
			return 0, ErrNotInstalled
		}
		return 0, fmt.Errorf("read Sysmon's log: %v", err)
	}
	return h, nil
}

func render(ev uintptr, buf *[]uint16) (string, error) {
	var used, props uint32
	for {
		var p uintptr
		if len(*buf) > 0 {
			p = uintptr(unsafe.Pointer(&(*buf)[0]))
		}
		r, _, err := procEvtRender.Call(0, ev, evtRenderEventXML, uintptr(len(*buf)*2), p,
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return syscall.UTF16ToString((*buf)[:used/2]), nil
		}
		if !errors.Is(err, errInsufficientBuffer) || used/2 <= uint32(len(*buf)) || used > 4<<20 {
			return "", err
		}
		*buf = make([]uint16, used/2+64)
	}
}

// Latest returns the newest record ID in Sysmon's log (0 when empty), so a
// reader can start from now instead of replaying history.
func Latest() (uint64, error) {
	h, err := query("*", evtQueryReverseDirection)
	if err != nil {
		return 0, err
	}
	defer procEvtClose.Call(h)
	var ev uintptr
	var n uint32
	if r, _, err := procEvtNext.Call(h, 1, uintptr(unsafe.Pointer(&ev)), 2000, 0, uintptr(unsafe.Pointer(&n))); r == 0 {
		if errors.Is(err, errNoMoreItems) {
			return 0, nil
		}
		return 0, err
	}
	defer procEvtClose.Call(ev)
	buf := make([]uint16, 4096)
	raw, err := render(ev, &buf)
	if err != nil {
		return 0, err
	}
	var x xmlEvent
	if e, ok := parseSystem(raw, &x); !ok {
		return 0, e
	}
	return x.System.EventRecordID, nil
}

// Since reads events newer than record after, oldest first, up to max. It
// returns the last record ID read (after, when none), and Tripsilk-usable
// events among them.
func Since(after uint64, max int) ([]Event, uint64, error) {
	h, err := query(fmt.Sprintf("*[System[EventRecordID>%d]]", after), evtQueryForwardDirection)
	if err != nil {
		return nil, after, err
	}
	defer procEvtClose.Call(h)
	var out []Event
	last := after
	buf := make([]uint16, 8192)
	evs := make([]uintptr, 64)
	read := 0
	for read < max {
		var n uint32
		r, _, err := procEvtNext.Call(h, uintptr(len(evs)), uintptr(unsafe.Pointer(&evs[0])), 0, 0, uintptr(unsafe.Pointer(&n)))
		if r == 0 {
			if errors.Is(err, errNoMoreItems) {
				break
			}
			return out, last, err
		}
		for i := 0; i < int(n); i++ {
			raw, rerr := render(evs[i], &buf)
			procEvtClose.Call(evs[i])
			if rerr != nil {
				continue
			}
			var x xmlEvent
			if _, ok := parseSystem(raw, &x); ok && x.System.EventRecordID > last {
				last = x.System.EventRecordID
			}
			if ev, ok := Parse(raw); ok {
				out = append(out, ev)
			}
		}
		read += int(n)
	}
	return out, last, nil
}
