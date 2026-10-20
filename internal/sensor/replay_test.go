package sensor

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Replays raw events recorded on real Windows (tripsilk-selftest -record)
// through the parsers. These are what Windows actually sent, so they catch
// layout and byte-order mistakes that synthetic payloads built from the
// same assumptions as the parser cannot. The user name in recorded paths is
// replaced with "user".
func TestReplayWindows11_26200(t *testing.T) { replay(t, "testdata/etw-win11-26200.jsonl") }

func replay(t *testing.T, path string) {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var head struct {
		Self, Child      uint32
		Listen4, Listen6 uint16 // recorded since the recorder kept them
	}
	sc.Scan()
	if err := json.Unmarshal(sc.Bytes(), &head); err != nil || head.Self == 0 || head.Child == 0 {
		t.Fatalf("header: %v %+v", err, head)
	}
	var started time.Time
	var stopped, connect4, accept4, connect6, dnsSeen, dnsAnswers bool
	var connectRemotePort, acceptLocalPort uint16
	for sc.Scan() {
		var r Raw
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		switch {
		case r.Provider == "process" && r.ID == idProcStart:
			pid, ppid, created, nt, ok := parseProcStart(r.Data, r.Time)
			if !ok || pid != head.Child || ppid != head.Self {
				t.Fatalf("start v%d: pid %d ppid %d, want %d %d", r.Version, pid, ppid, head.Child, head.Self)
			}
			if !plausible(created, r.Time, 5*time.Second) {
				t.Fatalf("start v%d: creation %v vs event %v", r.Version, created, r.Time)
			}
			if !strings.HasPrefix(nt, `\Device\`) || !strings.HasSuffix(nt, `\tripsilk-selftest.exe`) {
				t.Fatalf("start v%d: image %q", r.Version, nt)
			}
			started = created
		case r.Provider == "process" && r.ID == idProcStop:
			pid, created, ok := parseProcStop(r.Data, r.Time)
			if !ok || pid != head.Child || !created.Equal(started) {
				t.Fatalf("stop v%d: pid %d created %v, want %d %v", r.Version, pid, created, head.Child, started)
			}
			stopped = true
		case r.Provider == "network":
			v6 := r.ID == idTCP6Connect || r.ID == idTCP6Accept
			pid, local, remote, ok := parseTCP(v6, r.Data)
			if !ok || pid != head.Self || !remote.Addr().IsLoopback() || !local.Addr().IsLoopback() {
				t.Fatalf("tcp %d: pid %d %v -> %v", r.ID, pid, local, remote)
			}
			switch r.ID {
			case idTCP4Connect:
				connect4, connectRemotePort = true, remote.Port()
			case idTCP4Accept:
				accept4, acceptLocalPort = true, local.Port()
			case idTCP6Connect:
				connect6 = remote.Addr().Is6()
			}
		case r.Provider == "dns" && r.ID == idDNSQueryDone:
			name, _, answers, ok := parseDNS(r.Data)
			if !ok || r.PID != head.Self {
				t.Fatalf("dns: %q ok=%v header pid %d", name, ok, r.PID)
			}
			dnsSeen = true
			if name == "example.com" && len(answers) > 0 {
				dnsAnswers = true
			}
		}
	}
	// The listener's own port is what the client connected to: proves the
	// two ends and the port byte order agree.
	if connectRemotePort == 0 || connectRemotePort != acceptLocalPort {
		t.Errorf("connect remote port %d, accept local port %d", connectRemotePort, acceptLocalPort)
	}
	// Both ends agreeing doesn't prove byte order (a swap swaps both); the
	// port the test actually listened on does.
	if head.Listen4 != 0 && connectRemotePort != head.Listen4 {
		t.Errorf("connect remote port %d, but the recorder listened on %d: byte order wrong", connectRemotePort, head.Listen4)
	}
	for name, ok := range map[string]bool{"start": !started.IsZero(), "stop": stopped, "tcp4 connect": connect4,
		"tcp4 accept": accept4, "tcp6 connect": connect6, "dns": dnsSeen, "dns answers": dnsAnswers} {
		if !ok {
			t.Errorf("no %s event in the sample", name)
		}
	}
}
