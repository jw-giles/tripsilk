//go:build windows

package win

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// Folder locations come from Windows itself, never from environment
// variables: a program without admin rights can set %ProgramData% or
// %SystemRoot% for the user, and Tripsilk runs as admin with that environment.

var (
	shell32                       = syscall.NewLazyDLL("shell32.dll")
	ole32                         = syscall.NewLazyDLL("ole32.dll")
	procSHGetKnownFolderPath      = shell32.NewProc("SHGetKnownFolderPath")
	procCoTaskMemFree             = ole32.NewProc("CoTaskMemFree")
	procGetSystemDirectoryW       = kernel32.NewProc("GetSystemDirectoryW")
	procGetSystemWindowsDirectory = kernel32.NewProc("GetSystemWindowsDirectoryW")
)

// KnownFolder returns a known folder's path for the current user, or "".
func KnownFolder(id guid) string {
	var p *uint16
	r, _, _ := procSHGetKnownFolderPath.Call(uintptr(unsafe.Pointer(&id)), 0, 0, uintptr(unsafe.Pointer(&p)))
	if p != nil {
		defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(p)))
	}
	if r != 0 || p == nil {
		return ""
	}
	return syscall.UTF16ToString(unsafe.Slice(p, 32768))
}

func dirFrom(proc *syscall.LazyProc) string {
	buf := make([]uint16, 512)
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || int(n) >= len(buf) {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

// SystemDir is C:\Windows\System32 (or wherever Windows is installed).
func SystemDir() string { return dirFrom(procGetSystemDirectoryW) }

// WindowsDir is C:\Windows.
func WindowsDir() string { return dirFrom(procGetSystemWindowsDirectory) }

// systemTool resolves a bare tool name like "icacls" to its copy in
// System32, so a look-alike earlier on PATH can't stand in for it.
func systemTool(name string) string {
	if strings.ContainsAny(name, `\/`) {
		return name
	}
	sys := SystemDir()
	if sys == "" {
		return name
	}
	base := strings.ToLower(name)
	if !strings.HasSuffix(base, ".exe") {
		base += ".exe"
	}
	p := filepath.Join(sys, base)
	if base == "powershell.exe" {
		p = filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
		return p
	}
	return name
}
