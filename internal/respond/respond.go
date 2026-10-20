// Package respond carries out user-approved containment actions. Every
// action here is reversible: suspend has resume, a firewall block has
// unblock. Tripsilk never kills processes or deletes files; Defender owns
// quarantine and removal.
package respond

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// protected are image base names that must never be suspended or blocked.
// Suspending any of these can hang or crash Windows.
var protected = map[string]bool{
	"system": true, "registry": true, "smss.exe": true, "csrss.exe": true,
	"wininit.exe": true, "winlogon.exe": true, "services.exe": true,
	"lsass.exe": true, "lsaiso.exe": true, "svchost.exe": true,
	"dwm.exe": true, "fontdrvhost.exe": true, "explorer.exe": true,
	"msmpeng.exe": true, "nissrv.exe": true, "mpdefendercoreservice.exe": true,
	"securityhealthservice.exe": true, "memcompression": true,
	"conhost.exe": true, "sihost.exe": true, "ctfmon.exe": true,
}

// ErrProtected is returned when an action targets a protected process.
var ErrProtected = errors.New("refused: protected system process")

func baseName(image string) string {
	if i := strings.LastIndexAny(image, `\/`); i >= 0 {
		image = image[i+1:]
	}
	return strings.ToLower(image)
}

// CheckTarget validates a PID/image before any action.
func CheckTarget(pid uint32, image string) error {
	if pid == 0 || pid == 4 {
		return ErrProtected
	}
	if uint32(os.Getpid()) == pid {
		return errors.New("refused: cannot act on Tripsilk itself")
	}
	if image == "" {
		return errors.New("refused: process image unknown (exited or access denied)")
	}
	if strings.ContainsRune(image, '"') {
		return errors.New("refused: invalid program path")
	}
	if protected[baseName(image)] {
		return fmt.Errorf("%w (%s)", ErrProtected, baseName(image))
	}
	return nil
}

// RulePrefix starts every per-program firewall rule Tripsilk creates.
// LegacyRulePrefix is what aWall (Tripsilk's earlier name) used; rules with
// it are still recognized so they can be removed.
const (
	RulePrefix       = "Tripsilk block: "
	LegacyRulePrefix = "aWall block: "
)

// RuleName is the firewall rule name Tripsilk uses for an image. Stable so
// the same program is never blocked twice and unblock finds it.
func RuleName(image string) string {
	return RulePrefix + strings.ToLower(image)
}

// OwnRule reports whether a firewall rule name is one Tripsilk (or aWall)
// created, and returns the program path it names.
func OwnRule(name string) (image string, ok bool) {
	for _, p := range []string{RulePrefix, LegacyRulePrefix} {
		if strings.HasPrefix(name, p) {
			return strings.TrimPrefix(name, p), true
		}
	}
	return "", false
}
