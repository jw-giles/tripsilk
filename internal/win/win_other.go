//go:build !windows

package win

import (
	"errors"
	"os"
	"time"
)

// ImagePath is a stub off Windows.
func ImagePath(pid uint32) string { return "" }

// ProcessInfo is a stub off Windows.
func ProcessInfo(pid uint32) (string, time.Time) { return "", time.Time{} }

// SelfUsage is a stub off Windows.
func SelfUsage() (time.Duration, uint64, bool) { return 0, 0, false }

// ParentPID is a stub off Windows.
func ParentPID(pid uint32) (uint32, bool) { return 0, false }

// CommandLine is a stub off Windows.
func CommandLine(pid uint32) string { return "" }

// KnownFolder and the folder helpers are Windows-only; elsewhere they
// return "" and callers fall back to their own defaults.
func KnownFolder(id guid) string { return "" }
func SystemDir() string          { return "" }
func WindowsDir() string         { return "" }

// AdminOnlyDir just creates the folder off Windows.
func AdminOnlyDir(dir string) error { return os.MkdirAll(dir, 0o700) }

// Signed is a stub off Windows: nothing is trusted.
func Signed(path string) bool { return false }

// OpenAsUser opens a web page; only Windows is supported.
func OpenAsUser(url string) error { return errors.New("not supported on this OS") }

// AdminOwned: Tripsilk only installs on Windows; elsewhere (tests) every
// file counts as trusted.
func AdminOwned(path string) bool { return true }
