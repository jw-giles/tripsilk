//go:build windows

package shield

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"tripsilk/internal/win"
)

const (
	fileListDirectory = 0x0001
	// FILE_NAME | SIZE | LAST_WRITE: creations, deletions, renames and writes.
	watchFlags = 0x00000001 | 0x00000008 | 0x00000010
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetProcessIoCounters = kernel32.NewProc("GetProcessIoCounters")
)

// UserFolders returns the folders the shield watches: the ones that hold
// the files people would lose.
func UserFolders() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []string
	for _, name := range []string{"Documents", "Desktop", "Pictures", "Videos", "Music", "Downloads"} {
		p := filepath.Join(home, name)
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// Watcher reports every changed path under a set of folders, recursively.
type Watcher struct {
	mu      sync.Mutex
	handles []syscall.Handle
}

// Watch starts one loop per folder, calling emit with each changed path.
// It returns the folders it could watch.
func Watch(folders []string, emit func(path string)) (*Watcher, []string) {
	w := &Watcher{}
	var ok []string
	for _, dir := range folders {
		p, err := syscall.UTF16PtrFromString(dir)
		if err != nil {
			continue
		}
		h, err := syscall.CreateFile(p, fileListDirectory,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
			nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			continue
		}
		w.handles = append(w.handles, h)
		ok = append(ok, dir)
		go loop(dir, h, emit)
	}
	return w, ok
}

func loop(dir string, h syscall.Handle, emit func(string)) {
	buf := make([]byte, 64*1024)
	for {
		var n uint32
		if err := syscall.ReadDirectoryChanges(h, &buf[0], uint32(len(buf)), true,
			watchFlags, &n, nil, 0); err != nil {
			return
		}
		off := 0
		for n > 0 && off+12 <= int(n) {
			next := *(*uint32)(unsafe.Pointer(&buf[off]))
			nameLen := int(*(*uint32)(unsafe.Pointer(&buf[off+8])))
			if off+12+nameLen > int(n) {
				break
			}
			u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[off+12])), nameLen/2)
			emit(filepath.Join(dir, syscall.UTF16ToString(u16)))
			if next == 0 {
				break
			}
			off += int(next)
		}
	}
}

// Stop ends all watch loops.
func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, h := range w.handles {
		syscall.CancelIoEx(h, nil)
		syscall.CloseHandle(h)
	}
	w.handles = nil
}

// ioCounters mirrors IO_COUNTERS.
type ioCounters struct {
	ReadOps, WriteOps, OtherOps       uint64
	ReadBytes, WriteBytes, OtherBytes uint64
}

// WriteCounters samples total bytes written by each process. Image paths are
// looked up only when withImages is set, since each lookup opens the process
// again and the 2-second background sample doesn't need them.
func WriteCounters(pids []uint32, withImages bool) (map[uint32]uint64, map[uint32]string) {
	bytes := make(map[uint32]uint64, len(pids))
	images := make(map[uint32]string, len(pids))
	for _, pid := range pids {
		if pid <= 4 {
			continue
		}
		h, err := win.OpenProcess(win.ProcessQueryLimitedInformation, pid)
		if err != nil {
			continue
		}
		var c ioCounters
		r, _, _ := procGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&c)))
		syscall.CloseHandle(h)
		if r != 0 {
			bytes[pid] = c.WriteBytes
			if withImages {
				images[pid] = win.ImagePath(pid)
			}
		}
	}
	return bytes, images
}
