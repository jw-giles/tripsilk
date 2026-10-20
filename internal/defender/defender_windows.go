//go:build windows

package defender

import (
	"bytes"
	"fmt"
	"time"

	"tripsilk/internal/win"
)

// GetStatus queries Defender. On failure it returns a Status with
// Available=false and the error text, so the UI can show why.
func GetStatus() Status {
	out, err := win.PowerShell(30*time.Second, statusScript)
	if err != nil {
		return Status{Error: firstLine(out, err)}
	}
	s, err := parseStatus(bytes.TrimSpace(out))
	if err != nil {
		return Status{Error: err.Error()}
	}
	return s
}

// RecentThreats returns Defender's recent detections, newest first.
func RecentThreats() ([]Threat, error) {
	out, err := win.PowerShell(60*time.Second, threatsScript)
	if err != nil {
		return nil, fmt.Errorf("Get-MpThreatDetection: %s", firstLine(out, err))
	}
	return parseThreats(bytes.TrimSpace(out))
}

// StartScan asks Defender to scan. It returns when the scan finishes; full
// scans can take an hour or more, so callers run it in a goroutine.
func StartScan(kind ScanType) error {
	if kind != QuickScan && kind != FullScan {
		return fmt.Errorf("unknown scan type %q", kind)
	}
	timeout := 30 * time.Minute
	if kind == FullScan {
		timeout = 6 * time.Hour
	}
	out, err := win.PowerShell(timeout, "Start-MpScan -ScanType "+string(kind))
	if err != nil {
		return fmt.Errorf("Start-MpScan: %s", firstLine(out, err))
	}
	return nil
}

// UpdateSignatures asks Defender to fetch the latest definitions.
func UpdateSignatures() error {
	out, err := win.PowerShell(10*time.Minute, "Update-MpSignature")
	if err != nil {
		return fmt.Errorf("Update-MpSignature: %s", firstLine(out, err))
	}
	return nil
}

func firstLine(out []byte, err error) string {
	out = bytes.TrimSpace(out)
	if i := bytes.IndexByte(out, '\n'); i > 0 {
		out = out[:i]
	}
	if len(out) == 0 {
		return err.Error()
	}
	return string(bytes.TrimSpace(out))
}

// GetFolderProtection reads Controlled Folder Access.
func GetFolderProtection() FolderProtection {
	out, err := win.PowerShell(20*time.Second, "(Get-MpPreference).EnableControlledFolderAccess")
	if err != nil {
		return CFAUnknown
	}
	return ParseCFA(out)
}

// SetFolderProtection turns Controlled Folder Access on or off.
func SetFolderProtection(on bool) error {
	v := "Disabled"
	if on {
		v = "Enabled"
	}
	out, err := win.PowerShell(30*time.Second, "Set-MpPreference -EnableControlledFolderAccess "+v)
	if err != nil {
		return fmt.Errorf("Set-MpPreference: %s", firstLine(out, err))
	}
	return nil
}

// ScanPath has Defender scan one file or folder. Detections appear in
// Defender's threat history, where it quarantines them.
func ScanPath(path string) error {
	out, err := win.PowerShell(30*time.Minute, "Start-MpScan -ScanType CustomScan -ScanPath "+win.PSQuote(path))
	if err != nil {
		return fmt.Errorf("Start-MpScan: %s", firstLine(out, err))
	}
	return nil
}
