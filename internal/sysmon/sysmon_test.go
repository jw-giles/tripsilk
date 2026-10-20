package sysmon

import (
	"fmt"
	"testing"
)

// As EvtRender returns it on Windows 11 with Sysmon 15 (trimmed).
const sample1 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-17T22:01:02.1234567Z'/><EventRecordID>48211</EventRecordID><Correlation/><Execution ProcessID='3124' ThreadID='4410'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>PC</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-17 22:01:02.120</Data><Data Name='ProcessGuid'>{a}</Data><Data Name='ProcessId'>9120</Data><Data Name='Image'>C:\Windows\System32\cmd.exe</Data><Data Name='CommandLine'>cmd.exe /c echo hi &amp; whoami</Data><Data Name='User'>PC\user</Data><Data Name='Hashes'>SHA1=AAA,MD5=BBB,SHA256=2C1D0A8F4C2D7B6E9F0A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60,IMPHASH=CCC</Data><Data Name='ParentProcessId'>7000</Data><Data Name='ParentImage'>C:\x\claude.exe</Data></EventData></Event>`

func TestParseProcessCreate(t *testing.T) {
	ev, ok := Parse(sample1)
	if !ok || ev.ID != 1 || ev.RecordID != 48211 || ev.PID != 9120 || ev.Image != `C:\Windows\System32\cmd.exe` {
		t.Fatalf("%+v", ev)
	}
	if ev.SHA256 != "2c1d0a8f4c2d7b6e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60" {
		t.Fatalf("hash %q", ev.SHA256)
	}
	if ev.Fields["CommandLine"] != "cmd.exe /c echo hi & whoami" || ev.Fields["ParentImage"] != `C:\x\claude.exe` {
		t.Fatalf("fields %v", ev.Fields)
	}
	if _, ok := ev.Fields["ProcessGuid"]; ok {
		t.Fatal("unused field kept")
	}
	if ev.Time.IsZero() || ev.Time.Nanosecond() != 123456700 {
		t.Fatalf("time %v", ev.Time)
	}
}

func TestParseOthers(t *testing.T) {
	dns := `<Event><System><EventID>22</EventID><EventRecordID>9</EventRecordID><TimeCreated SystemTime='2026-10-17T22:01:02Z'/></System><EventData><Data Name='ProcessId'>5</Data><Data Name='QueryName'>api.telegram.org</Data><Data Name='QueryResults'>::ffff:149.154.167.220;</Data><Data Name='Image'>C:\x\a.exe</Data></EventData></Event>`
	if ev, ok := Parse(dns); !ok || ev.Fields["QueryName"] != "api.telegram.org" || ev.PID != 5 {
		t.Fatalf("%+v", ev)
	}
	if _, ok := Parse(`<Event><System><EventID>11</EventID></System></Event>`); ok {
		t.Fatal("unused event ID parsed")
	}
	if _, ok := Parse("not xml"); ok {
		t.Fatal("junk parsed")
	}
	if HashFrom("MD5=1,SHA256=short") != "" || HashFrom("") != "" {
		t.Fatal("bad hash accepted")
	}
}

func TestHashesMatchImageAndAreBounded(t *testing.T) {
	h := NewHashes(3)
	h.Add(1, `C:\a.exe`, "s1")
	if s, ok := h.Get(1, `c:\A.exe`); !ok || s != "s1" {
		t.Fatal("lookup")
	}
	if _, ok := h.Get(1, `C:\b.exe`); ok {
		t.Fatal("reused PID matched another program")
	}
	for i := 2; i < 10; i++ {
		h.Add(uint32(i), fmt.Sprint(i), "s")
	}
	if len(h.m) != 3 || len(h.order) != 3 {
		t.Fatalf("unbounded: %d", len(h.m))
	}
	h.Add(0, "x", "s")
	h.Add(5, "x", "")
	if len(h.m) != 3 {
		t.Fatal("empty entries kept")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sample1)
	f.Fuzz(func(t *testing.T, s string) { Parse(s) })
}
