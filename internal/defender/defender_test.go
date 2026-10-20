package defender

import "testing"

func TestParseStatusAndHealth(t *testing.T) {
	out := []byte(`{"AntivirusEnabled":true,"RealTimeProtectionEnabled":false,"IsTamperProtected":true,"AntivirusSignatureVersion":"1.419.1.0","AntivirusSignatureAge":5,"QuickScanAge":1,"QuickScanEndTime":"2026-10-04T09:00:00.0000000-07:00","FullScanEndTime":null}`)
	s, err := parseStatus(out)
	if err != nil {
		t.Fatal(err)
	}
	if s.LastQuickScan.IsZero() || !s.LastFullScan.IsZero() {
		t.Fatalf("scan times wrong: %+v", s)
	}
	ok, issues := s.Healthy()
	if ok || len(issues) != 2 {
		t.Fatalf("expected 2 issues (RTP off, old sigs), got %v", issues)
	}
}

func TestParseThreatsSingleAndList(t *testing.T) {
	one := []byte(`{"Name":"Trojan:Win32/Test","Severity":"5","Resources":["file:_C:\\x.exe"],"Detected":"2026-10-01T10:00:00.0000000Z","Action":"3"}`)
	ts, err := parseThreats(one)
	if err != nil || len(ts) != 1 {
		t.Fatalf("single: %v %v", ts, err)
	}
	if ts[0].Severity != "severe" || ts[0].Action != "quarantined" || ts[0].Detected.IsZero() {
		t.Fatalf("mapping wrong: %+v", ts[0])
	}
	empty, err := parseThreats(nil)
	if err != nil || empty != nil {
		t.Fatal("empty output should yield no threats")
	}
}

// Windows PowerShell 5.1 emits {} for a missing calculated property; this
// failed the whole status read on a real machine (self-test, 2026-10-05).
func TestParseStatusToleratesEmptyObject(t *testing.T) {
	out := []byte(`{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"IsTamperProtected":true,"AntivirusSignatureVersion":"1.1","AntivirusSignatureAge":0,"QuickScanAge":0,"QuickScanEndTime":"2026-10-04T09:00:00.0000000-07:00","FullScanEndTime":{}}`)
	s, err := parseStatus(out)
	if err != nil {
		t.Fatal(err)
	}
	if !s.LastFullScan.IsZero() || s.LastQuickScan.IsZero() {
		t.Fatalf("times: %+v", s)
	}
}

func TestParseCFA(t *testing.T) {
	for in, want := range map[string]FolderProtection{"0\r\n": CFAOff, "1": CFAOn, "2": CFAAudit, "": CFAUnknown, "x": CFAUnknown} {
		if got := ParseCFA([]byte(in)); got != want {
			t.Errorf("%q: got %s want %s", in, got, want)
		}
	}
}
