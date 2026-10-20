//go:build windows

package agentguard

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"tripsilk/internal/win"
)

// SnapshotProcs lists running processes with parent PID, image path and
// creation time. Command lines are not read here; call FillCmdLine only for
// processes being reported, since reading them costs a syscall each.
func SnapshotProcs() ([]Proc, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snap)
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := syscall.Process32First(snap, &e); err != nil {
		return nil, err
	}
	var out []Proc
	for {
		p := Proc{
			PID:  e.ProcessID,
			PPID: e.ParentProcessID,
			Name: syscall.UTF16ToString(e.ExeFile[:]),
		}
		p.Image, p.Created = win.ProcessInfo(p.PID)
		out = append(out, p)
		if err := syscall.Process32Next(snap, &e); err != nil {
			break
		}
	}
	return out, nil
}

// FillCmdLine reads the command line for p.
func FillCmdLine(p *Proc) { p.CmdLine = win.CommandLine(p.PID) }

// ---- Startup entries ----

var (
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	procRegEnumValue = advapi32.NewProc("RegEnumValueW")
)

const (
	regSZ       = 1
	regExpandSZ = 2
)

type runKey struct {
	root  syscall.Handle
	path  string
	label string
}

var runKeys = []runKey{
	{syscall.HKEY_CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, "Run key (you)"},
	{syscall.HKEY_CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "RunOnce key (you)"},
	{syscall.HKEY_LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, "Run key (all users)"},
	{syscall.HKEY_LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "RunOnce key (all users)"},
	{syscall.HKEY_LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "Run key (all users, 32-bit)"},
}

func readRunKey(k runKey) ([]StartupEntry, error) {
	var h syscall.Handle
	p, _ := syscall.UTF16PtrFromString(k.path)
	if err := syscall.RegOpenKeyEx(k.root, p, 0, syscall.KEY_READ, &h); err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return nil, nil // key absent: no entries
		}
		return nil, err
	}
	defer syscall.RegCloseKey(h)
	var out []StartupEntry
	const errMoreData = 234
	dataSize := uint32(65536)
	for i := uint32(0); i < 10000; i++ {
		name := make([]uint16, 16384)
		nameLen := uint32(len(name))
		data := make([]byte, dataSize)
		dataLen := uint32(len(data))
		var typ uint32
		r, _, _ := procRegEnumValue.Call(uintptr(h), uintptr(i),
			uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLen)), 0,
			uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&dataLen)))
		if r == 259 { // ERROR_NO_MORE_ITEMS
			break
		}
		if r == errMoreData && dataLen > dataSize && dataLen <= 16<<20 {
			// An oversized value: retry this index with room for it, so one
			// huge value can't hide the whole key from the startup watch.
			dataSize = dataLen
			i--
			continue
		}
		if r == errMoreData {
			// Too big to read at all. Report it by name: a startup entry
			// that large is itself worth a look.
			nameLen = uint32(len(name))
			r, _, _ = procRegEnumValue.Call(uintptr(h), uintptr(i),
				uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLen)), 0, 0, 0, 0)
			if r == 0 {
				out = append(out, StartupEntry{Where: k.label, Name: syscall.UTF16ToString(name[:nameLen]),
					Command: fmt.Sprintf("(value too large to read: %d bytes)", dataLen)})
				continue
			}
		}
		if r != 0 {
			return out, fmt.Errorf("RegEnumValue: error %d", r)
		}
		cmd := ""
		if (typ == regSZ || typ == regExpandSZ) && dataLen >= 2 {
			u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&data[0])), dataLen/2)
			cmd = syscall.UTF16ToString(u16)
		}
		out = append(out, StartupEntry{Where: k.label, Name: syscall.UTF16ToString(name[:nameLen]), Command: cmd})
	}
	return out, nil
}

func startupFolders() []struct{ dir, label string } {
	var out []struct{ dir, label string }
	if a := win.AppData(); a != "" {
		out = append(out, struct{ dir, label string }{filepath.Join(a, `Microsoft\Windows\Start Menu\Programs\Startup`), "Startup folder (you)"})
	}
	if pd := win.ProgramData(); pd != "" {
		out = append(out, struct{ dir, label string }{filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\StartUp`), "Startup folder (all users)"})
	}
	return out
}

func readStartupFolder(dir, label string) ([]StartupEntry, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []StartupEntry
	for _, e := range ents {
		if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
			continue
		}
		info, err := e.Info()
		size := int64(0)
		if err == nil {
			size = info.Size()
		}
		out = append(out, StartupEntry{Where: label, Name: e.Name(),
			Command: fmt.Sprintf("%s (%d bytes)", filepath.Join(dir, e.Name()), size)})
	}
	return out, nil
}

// readTasks walks the scheduled task store. Needs administrator.
func readTasks() ([]StartupEntry, error) {
	root := win.SystemTool("Tasks")
	var out []StartupEntry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			return nil // skip unreadable subfolders
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		data, rerr := os.ReadFile(path)
		cmd := ""
		if rerr == nil {
			cmd = taskCommand(data)
		}
		out = append(out, StartupEntry{Where: "Scheduled task", Name: `\` + rel, Command: cmd})
		return nil
	})
	return out, err
}

// StartupEntries reads every startup source. failed marks sources that
// couldn't be read (e.g. scheduled tasks without administrator rights).
func StartupEntries() (map[string][]StartupEntry, map[string]bool) {
	cur := map[string][]StartupEntry{}
	failed := map[string]bool{}
	for _, k := range runKeys {
		e, err := readRunKey(k)
		if err != nil {
			failed[k.label] = true
			continue
		}
		cur[k.label] = e
	}
	for _, f := range startupFolders() {
		e, err := readStartupFolder(f.dir, f.label)
		if err != nil {
			failed[f.label] = true
			continue
		}
		cur[f.label] = e
	}
	if e, err := readTasks(); err != nil {
		failed["Scheduled task"] = true
	} else {
		cur["Scheduled task"] = e
	}
	return cur, failed
}
