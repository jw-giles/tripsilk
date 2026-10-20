//go:build windows

package eventlog

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"tripsilk/internal/engine"
)

var (
	advapi32                 = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKeyExW      = advapi32.NewProc("RegCreateKeyExW")
	procRegSetValueExW       = advapi32.NewProc("RegSetValueExW")
	procRegDeleteKeyW        = advapi32.NewProc("RegDeleteKeyW")
	procRegisterEventSourceW = advapi32.NewProc("RegisterEventSourceW")
	procReportEventW         = advapi32.NewProc("ReportEventW")
	procDeregisterEventSrc   = advapi32.NewProc("DeregisterEventSource")
)

const (
	hklm          = syscall.Handle(0x80000002)
	keyAllAccess  = 0xF003F
	regSZExpand   = 2
	regDWORD      = 4
	keyPath       = `SYSTEM\CurrentControlSet\Services\EventLog\Application\` + Source
	eventTypesAll = 7 // error, warning, information
)

// messageFile is .NET's message file, whose every event ID reads "%1", so
// Event Viewer shows Tripsilk's text as written instead of "the description
// for Event ID ... cannot be found". It ships with Windows 10 and 11.
func messageFile() string {
	win := os.Getenv("SystemRoot")
	if win == "" {
		win = `C:\Windows`
	}
	for _, fw := range []string{"Framework64", "Framework"} {
		p := filepath.Join(win, "Microsoft.NET", fw, "v4.0.30319", "EventLogMessages.dll")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Register creates the event source (needs admin). Safe to repeat.
func Register() error {
	k, err := syscall.UTF16PtrFromString(keyPath)
	if err != nil {
		return err
	}
	var h syscall.Handle
	if r, _, _ := procRegCreateKeyExW.Call(uintptr(hklm), uintptr(unsafe.Pointer(k)), 0, 0, 0, keyAllAccess, 0,
		uintptr(unsafe.Pointer(&h)), 0); r != 0 {
		return errors.New("register the event source: " + syscall.Errno(r).Error())
	}
	defer syscall.RegCloseKey(h)
	if mf := messageFile(); mf != "" {
		v, _ := syscall.UTF16FromString(mf)
		name, _ := syscall.UTF16PtrFromString("EventMessageFile")
		if r, _, _ := procRegSetValueExW.Call(uintptr(h), uintptr(unsafe.Pointer(name)), 0, regSZExpand,
			uintptr(unsafe.Pointer(&v[0])), uintptr(len(v)*2)); r != 0 {
			return errors.New("register the event source: " + syscall.Errno(r).Error())
		}
	}
	types := uint32(eventTypesAll)
	name, _ := syscall.UTF16PtrFromString("TypesSupported")
	if r, _, _ := procRegSetValueExW.Call(uintptr(h), uintptr(unsafe.Pointer(name)), 0, regDWORD,
		uintptr(unsafe.Pointer(&types)), 4); r != 0 {
		return errors.New("register the event source: " + syscall.Errno(r).Error())
	}
	return nil
}

// Unregister removes the event source (events already written stay).
func Unregister() error {
	k, _ := syscall.UTF16PtrFromString(keyPath)
	if r, _, _ := procRegDeleteKeyW.Call(uintptr(hklm), uintptr(unsafe.Pointer(k))); r != 0 && syscall.Errno(r) != syscall.ERROR_FILE_NOT_FOUND {
		return errors.New("remove the event source: " + syscall.Errno(r).Error())
	}
	return nil
}

// Writer writes alerts to the Application log.
type Writer struct {
	mu sync.Mutex
	h  uintptr
}

func Open() (*Writer, error) {
	src, _ := syscall.UTF16PtrFromString(Source)
	h, _, err := procRegisterEventSourceW.Call(0, uintptr(unsafe.Pointer(src)))
	if h == 0 {
		return nil, errors.New("open the event log: " + err.Error())
	}
	return &Writer{h: h}, nil
}

func (w *Writer) Write(a engine.Alert) error {
	text, err := syscall.UTF16PtrFromString(stripNUL(Text(a)))
	if err != nil {
		return err
	}
	strs := [1]*uint16{text}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.h == 0 {
		return errors.New("event log closed")
	}
	if r, _, e := procReportEventW.Call(w.h, uintptr(LevelOf(a.Severity)), 0, uintptr(IDOf(a.Source)), 0, 1, 0,
		uintptr(unsafe.Pointer(&strs[0])), 0); r == 0 {
		return errors.New("write to the event log: " + e.Error())
	}
	return nil
}

func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.h != 0 {
		procDeregisterEventSrc.Call(w.h)
		w.h = 0
	}
}
