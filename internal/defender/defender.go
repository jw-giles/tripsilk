// Package defender reads Microsoft Defender's state and asks it to scan,
// through the Defender PowerShell module. Tripsilk never replaces Defender's
// detection; it surfaces it next to the AI-specific signals.
package defender

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Status is the subset of Get-MpComputerStatus the dashboard shows.
type Status struct {
	Available          bool      `json:"available"`
	Error              string    `json:"error,omitempty"`
	AntivirusEnabled   bool      `json:"antivirusEnabled"`
	RealTimeProtection bool      `json:"realTimeProtection"`
	TamperProtected    bool      `json:"tamperProtected"`
	SignatureVersion   string    `json:"signatureVersion"`
	SignatureAgeDays   int       `json:"signatureAgeDays"`
	LastQuickScan      time.Time `json:"lastQuickScan"`
	LastFullScan       time.Time `json:"lastFullScan"`
	QuickScanAgeDays   int       `json:"quickScanAgeDays"`
}

// Threat is one Defender detection.
type Threat struct {
	Name      string    `json:"name"`
	Severity  string    `json:"severity"`
	Resources []string  `json:"resources"`
	Detected  time.Time `json:"detected"`
	Action    string    `json:"action"`
}

// Healthy reports whether Defender looks properly configured; the issues
// slice lists what's wrong in plain words for the UI.
func (s Status) Healthy() (bool, []string) {
	var issues []string
	if !s.Available {
		return false, []string{"Microsoft Defender status unavailable: " + s.Error}
	}
	if !s.AntivirusEnabled {
		issues = append(issues, "Antivirus is turned off")
	}
	if !s.RealTimeProtection {
		issues = append(issues, "Real-time protection is off")
	}
	if !s.TamperProtected {
		issues = append(issues, "Tamper protection is off")
	}
	if s.SignatureAgeDays > 3 {
		issues = append(issues, fmt.Sprintf("Virus definitions are %d days old", s.SignatureAgeDays))
	}
	if s.QuickScanAgeDays > 7 {
		issues = append(issues, fmt.Sprintf("No quick scan in %d days", s.QuickScanAgeDays))
	}
	return len(issues) == 0, issues
}

// rawStatus matches the JSON emitted by statusScript.
type rawStatus struct {
	AntivirusEnabled          bool
	RealTimeProtectionEnabled bool
	IsTamperProtected         bool
	AntivirusSignatureVersion string
	AntivirusSignatureAge     int
	QuickScanAge              int
	QuickScanEndTime          looseString
	FullScanEndTime           looseString
}

// looseString accepts a JSON string and treats anything else (null, {}, a
// number) as empty. Windows PowerShell 5.1 serializes a missing value from a
// calculated property as {} rather than null, which a plain string field
// rejects, failing the whole status read.
type looseString string

func (l *looseString) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*l = looseString(s)
	} else {
		*l = ""
	}
	return nil
}

const statusScript = `Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureVersion,AntivirusSignatureAge,QuickScanAge,@{n='QuickScanEndTime';e={if($_.QuickScanEndTime){$_.QuickScanEndTime.ToString('o')}else{''}}},@{n='FullScanEndTime';e={if($_.FullScanEndTime){$_.FullScanEndTime.ToString('o')}else{''}}} | ConvertTo-Json -Compress`

func parseStatus(out []byte) (Status, error) {
	var r rawStatus
	if err := json.Unmarshal(out, &r); err != nil {
		return Status{}, fmt.Errorf("parse Defender status: %w", err)
	}
	s := Status{
		Available:          true,
		AntivirusEnabled:   r.AntivirusEnabled,
		RealTimeProtection: r.RealTimeProtectionEnabled,
		TamperProtected:    r.IsTamperProtected,
		SignatureVersion:   r.AntivirusSignatureVersion,
		SignatureAgeDays:   r.AntivirusSignatureAge,
		QuickScanAgeDays:   r.QuickScanAge,
	}
	s.LastQuickScan, _ = time.Parse(time.RFC3339Nano, string(r.QuickScanEndTime))
	s.LastFullScan, _ = time.Parse(time.RFC3339Nano, string(r.FullScanEndTime))
	return s, nil
}

const threatsScript = `@(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 50 | ForEach-Object { $t = Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue; [pscustomobject]@{ Name = if($t){$t.ThreatName}else{"ThreatID " + $_.ThreatID}; Severity = if($t){[string]$t.SeverityID}else{""}; Resources = @($_.Resources); Detected = $_.InitialDetectionTime.ToString('o'); Action = [string]$_.ThreatStatusID } }) | ConvertTo-Json -Compress -Depth 3`

var severityNames = map[string]string{"0": "unknown", "1": "low", "2": "moderate", "4": "high", "5": "severe"}

// Threat status IDs per Defender docs (subset).
var actionNames = map[string]string{
	"0": "unknown", "1": "detected", "2": "cleaned", "3": "quarantined",
	"4": "removed", "5": "allowed", "6": "blocked", "102": "quarantine failed",
	"103": "remove failed", "104": "allow failed", "105": "abandoned", "107": "block failed",
}

func parseThreats(out []byte) ([]Threat, error) {
	if len(out) == 0 {
		return nil, nil
	}
	// ConvertTo-Json emits a bare object for a single element; normalize.
	if out[0] == '{' {
		out = append(append([]byte{'['}, out...), ']')
	}
	var raw []struct {
		Name      string
		Severity  string
		Resources []string
		Detected  string
		Action    string
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("parse Defender threats: %w", err)
	}
	threats := make([]Threat, 0, len(raw))
	for _, r := range raw {
		t := Threat{Name: r.Name, Resources: r.Resources}
		t.Severity = severityNames[r.Severity]
		if t.Severity == "" {
			t.Severity = r.Severity
		}
		t.Action = actionNames[r.Action]
		if t.Action == "" {
			t.Action = r.Action
		}
		t.Detected, _ = time.Parse(time.RFC3339Nano, r.Detected)
		threats = append(threats, t)
	}
	return threats, nil
}

// ScanType is a Defender scan kind.
type ScanType string

const (
	QuickScan ScanType = "QuickScan"
	FullScan  ScanType = "FullScan"
)

// FolderProtection is Controlled Folder Access: Windows' built-in block on
// unapproved programs changing protected folders (Documents, Pictures...).
type FolderProtection string

const (
	CFAOff     FolderProtection = "off"
	CFAOn      FolderProtection = "on"
	CFAAudit   FolderProtection = "audit" // logs, doesn't block
	CFAUnknown FolderProtection = "unknown"
)

// ParseCFA maps Get-MpPreference's EnableControlledFolderAccess value.
func ParseCFA(out []byte) FolderProtection {
	switch strings.TrimSpace(string(out)) {
	case "0":
		return CFAOff
	case "1":
		return CFAOn
	case "2", "3", "4":
		return CFAAudit
	}
	return CFAUnknown
}
