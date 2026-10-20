//go:build windows

// Package win holds small Win32 helpers shared by the platform packages.
// Standard library only: syscall.NewLazyDLL, no x/sys dependency.
package win

import (
	"context"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	ProcessQueryLimitedInformation = 0x1000
	ProcessSuspendResume           = 0x0800
	createNoWindow                 = 0x08000000
)

// OpenProcess wraps kernel32!OpenProcess.
func OpenProcess(access uint32, pid uint32) (syscall.Handle, error) {
	r, _, e := procOpenProcess.Call(uintptr(access), 0, uintptr(pid))
	if r == 0 {
		return 0, e
	}
	return syscall.Handle(r), nil
}

// ImagePath returns the full executable path for a PID, or "" if it can't be
// opened (protected processes, already exited, insufficient rights).
func ImagePath(pid uint32) string {
	if pid == 0 || pid == 4 {
		return "System"
	}
	h, err := OpenProcess(ProcessQueryLimitedInformation, pid)
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	r, _, _ := procQueryFullProcessImageNameW.Call(uintptr(h), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

// Run executes a command with no console window and a timeout, returning
// combined output.
func Run(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemTool(name), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd.CombinedOutput()
}

// PowerShell runs a script non-interactively.
func PowerShell(timeout time.Duration, script string) ([]byte, error) {
	// Execution policy only governs script files, not -Command, so it is left
	// at the machine's setting.
	return Run(timeout, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-Command", script)
}

// RunRaw runs exe with an exact command line, bypassing Go's argument
// escaping. Needed for netsh, which expects name="value" quoting rather than
// a fully quoted "name=value" token. Callers must not pass user-controlled
// text containing double quotes.
func RunRaw(timeout time.Duration, exe, cmdline string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow, CmdLine: cmdline}
	return cmd.CombinedOutput()
}

var (
	ntdll                         = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
)

// ProcessInfo returns a process's image path and creation time with one
// handle. Either may be empty/zero if the process can't be opened.
func ProcessInfo(pid uint32) (image string, created time.Time) {
	if pid == 0 || pid == 4 {
		return "System", time.Time{}
	}
	h, err := OpenProcess(ProcessQueryLimitedInformation, pid)
	if err != nil {
		return "", time.Time{}
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	if r, _, _ := procQueryFullProcessImageNameW.Call(uintptr(h), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r != 0 {
		image = syscall.UTF16ToString(buf[:size])
	}
	var c, e, k, u syscall.Filetime
	if syscall.GetProcessTimes(h, &c, &e, &k, &u) == nil {
		created = time.Unix(0, c.Nanoseconds())
	}
	return image, created
}

var procGetProcessMemoryInfo = kernel32.NewProc("K32GetProcessMemoryInfo")

// SelfUsage returns Tripsilk's own processor time so far and its working
// set (memory in use), for the dashboard's resource line.
func SelfUsage() (cpu time.Duration, workingSet uint64, ok bool) {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, 0, false
	}
	var c, e, k, u syscall.Filetime
	if syscall.GetProcessTimes(h, &c, &e, &k, &u) != nil {
		return 0, 0, false
	}
	ticks := func(f syscall.Filetime) int64 { return int64(f.HighDateTime)<<32 | int64(f.LowDateTime) }
	cpu = time.Duration((ticks(k) + ticks(u)) * 100)
	// PROCESS_MEMORY_COUNTERS (x64): cb, PageFaultCount, then SIZE_T fields.
	var pmc struct {
		Cb                         uint32
		PageFaultCount             uint32
		PeakWorkingSetSize         uintptr
		WorkingSetSize             uintptr
		QuotaPeakPagedPoolUsage    uintptr
		QuotaPagedPoolUsage        uintptr
		QuotaPeakNonPagedPoolUsage uintptr
		QuotaNonPagedPoolUsage     uintptr
		PagefileUsage              uintptr
		PeakPagefileUsage          uintptr
	}
	pmc.Cb = uint32(unsafe.Sizeof(pmc))
	if r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.Cb)); r != 0 {
		workingSet = uint64(pmc.WorkingSetSize)
	}
	return cpu, workingSet, true
}

// ParentPID reads a live process's parent PID from the kernel
// (ProcessBasicInformation.InheritedFromUniqueProcessId). ok is false if the
// process can't be opened.
func ParentPID(pid uint32) (uint32, bool) {
	h, err := OpenProcess(ProcessQueryLimitedInformation, pid)
	if err != nil {
		return 0, false
	}
	defer syscall.CloseHandle(h)
	var pbi struct {
		ExitStatus      uintptr // NTSTATUS, padded
		PebBaseAddress  uintptr
		AffinityMask    uintptr
		BasePriority    uintptr // KPRIORITY, padded
		UniqueProcessID uintptr
		InheritedFrom   uintptr
	}
	var ret uint32
	status, _, _ := procNtQueryInformationProcess.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi), uintptr(unsafe.Pointer(&ret)))
	if status != 0 || uint32(pbi.UniqueProcessID) != pid {
		return 0, false
	}
	return uint32(pbi.InheritedFrom), true
}

// CommandLine reads a process's command line via
// NtQueryInformationProcess(ProcessCommandLineInformation = 60), available
// on Windows 8.1 and later. Returns "" when it can't be read.
func CommandLine(pid uint32) string {
	h, err := OpenProcess(ProcessQueryLimitedInformation, pid)
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(h)
	const processCommandLineInformation = 60
	buf := make([]byte, 8192)
	for attempt := 0; attempt < 3; attempt++ {
		var ret uint32
		status, _, _ := procNtQueryInformationProcess.Call(uintptr(h), processCommandLineInformation,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&ret)))
		if status == 0xC0000004 && ret > uint32(len(buf)) && ret < 1<<20 { // STATUS_INFO_LENGTH_MISMATCH
			buf = make([]byte, ret)
			continue
		}
		if status != 0 {
			return ""
		}
		// The buffer starts with a UNICODE_STRING whose Buffer pointer
		// points into this same allocation.
		type unicodeString struct {
			Length, MaximumLength uint16
			Buffer                uintptr
		}
		us := (*unicodeString)(unsafe.Pointer(&buf[0]))
		base := uintptr(unsafe.Pointer(&buf[0]))
		off := us.Buffer - base
		n := uintptr(us.Length)
		if us.Buffer < base || off+n > uintptr(len(buf)) || n%2 != 0 {
			return ""
		}
		u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[off])), n/2)
		return syscall.UTF16ToString(u16)
	}
	return ""
}

// OpenAsUser opens a web page in the signed-in user's default browser
// without passing on Tripsilk's admin rights. Starting the browser directly
// from an elevated process gives it admin rights too; handing the link to
// explorer.exe gets the already-running, unelevated Explorer to open it.
// Explorer exits with status 1 even when it worked, so the exit status
// isn't checked.
func OpenAsUser(url string) error {
	cmd := exec.Command(WindowsDir()+`\explorer.exe`, url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}
