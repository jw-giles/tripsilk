//go:build windows

package respond

import (
	"fmt"
	"strings"
	"syscall"
	"time"

	"tripsilk/internal/win"
)

var (
	ntdll                = syscall.NewLazyDLL("ntdll.dll")
	procNtSuspendProcess = ntdll.NewProc("NtSuspendProcess")
	procNtResumeProcess  = ntdll.NewProc("NtResumeProcess")
)

func ntProcessCall(proc *syscall.LazyProc, pid uint32) error {
	h, err := win.OpenProcess(win.ProcessSuspendResume, pid)
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer syscall.CloseHandle(h)
	status, _, _ := proc.Call(uintptr(h))
	if status != 0 {
		return fmt.Errorf("NTSTATUS 0x%08x", uint32(status))
	}
	return nil
}

// Suspend freezes every thread in the process. Reversible with Resume.
// The image is re-read at call time so a recycled PID can't redirect the
// action to a different program.
func Suspend(pid uint32, expectedImage string) error {
	if err := verify(pid, expectedImage); err != nil {
		return err
	}
	return ntProcessCall(procNtSuspendProcess, pid)
}

// Resume undoes Suspend.
func Resume(pid uint32, expectedImage string) error {
	if err := verify(pid, expectedImage); err != nil {
		return err
	}
	return ntProcessCall(procNtResumeProcess, pid)
}

func verify(pid uint32, expectedImage string) error {
	current := win.ImagePath(pid)
	if err := CheckTarget(pid, current); err != nil {
		return err
	}
	if expectedImage != "" && !strings.EqualFold(current, expectedImage) {
		return fmt.Errorf("refused: PID %d is now %s, not %s", pid, current, expectedImage)
	}
	return nil
}

// Block adds an outbound Windows Firewall rule for the program. Inbound is
// left alone: the threat model is a hijacked agent phoning out.
func Block(image string) (string, error) {
	if err := CheckTarget(1, image); err != nil { // PID irrelevant for path rules
		return "", err
	}
	name := RuleName(image)
	if exists(name) {
		return name, nil
	}
	out, err := netsh(`advfirewall firewall add rule name="` + name +
		`" dir=out action=block program="` + image + `" enable=yes`)
	if err != nil {
		return "", fmt.Errorf("netsh add rule: %s", strings.TrimSpace(string(out)))
	}
	return name, nil
}

// Unblock removes a rule Tripsilk created. Only names with Tripsilk's prefix
// are accepted so this can't be used to delete the user's own rules.
func Unblock(ruleName string) error {
	if _, ok := OwnRule(ruleName); !ok {
		return fmt.Errorf("refused: %q is not a Tripsilk rule", ruleName)
	}
	if strings.ContainsRune(ruleName, '"') {
		return fmt.Errorf("refused: invalid rule name")
	}
	out, err := netsh(`advfirewall firewall delete rule name="` + ruleName + `"`)
	if err != nil {
		return fmt.Errorf("netsh delete rule: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func exists(name string) bool {
	_, err := netsh(`advfirewall firewall show rule name="` + name + `"`)
	return err == nil
}

func netsh(args string) ([]byte, error) {
	exe := win.SystemTool("netsh.exe")
	return win.RunRaw(20*time.Second, exe, `netsh.exe `+args)
}

// Terminate ends a process for good. Reversible actions are preferred, so
// this is only called on explicit user confirmation after a suspend.
func Terminate(pid uint32, expectedImage string) error {
	if err := verify(pid, expectedImage); err != nil {
		return err
	}
	const processTerminate = 0x0001
	h, err := win.OpenProcess(processTerminate, pid)
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer syscall.CloseHandle(h)
	if err := syscall.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("terminate %d: %w", pid, err)
	}
	return nil
}

const allOutboundRule = "Tripsilk emergency: block all outbound"

// Rules from aWall, Tripsilk's earlier name. legacyOutboundRule is the old
// emergency block; legacyAllowRule was an exception aWall 0.6 and earlier
// added for itself. Both are removed whenever the block is set or cleared.
const (
	legacyOutboundRule = "aWall emergency: block all outbound"
	legacyAllowRule    = legacyOutboundRule + " (allow aWall)"
)

// BlockAllOutbound blocks every program's outbound connections, for a live
// intrusion. There is deliberately no exception for Tripsilk: in Windows
// Firewall a block rule always beats an allow rule, and Tripsilk's dashboard
// is local and doesn't need the internet. Defender updates are blocked too
// while disconnected.
func BlockAllOutbound() error {
	// Remove any earlier copy so repeated clicks don't stack rules.
	netsh(`advfirewall firewall delete rule name="` + allOutboundRule + `"`)
	netsh(`advfirewall firewall delete rule name="` + legacyOutboundRule + `"`)
	netsh(`advfirewall firewall delete rule name="` + legacyAllowRule + `"`)
	if out, err := netsh(`advfirewall firewall add rule name="` + allOutboundRule +
		`" dir=out action=block enable=yes`); err != nil {
		return fmt.Errorf("block outbound: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// UnblockAllOutbound removes the emergency block. It reports failure when
// the rule is still in place afterwards.
func UnblockAllOutbound() error {
	netsh(`advfirewall firewall delete rule name="` + legacyAllowRule + `"`)
	netsh(`advfirewall firewall delete rule name="` + legacyOutboundRule + `"`)
	out, err := netsh(`advfirewall firewall delete rule name="` + allOutboundRule + `"`)
	if err != nil && OutboundBlocked() {
		return fmt.Errorf("remove block: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// OutboundBlocked reports whether the emergency block rule exists, so the
// dashboard shows Reconnect even after Tripsilk restarts.
func OutboundBlocked() bool { return exists(allOutboundRule) || exists(legacyOutboundRule) }
