package sensor

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
	"unicode/utf16"
)

func u16z(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u)+2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func le64(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }
func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func toFiletime(t time.Time) uint64 { return uint64(t.UnixNano()/100 + 116444736000000000) }

func TestProcStartLayouts(t *testing.T) {
	when := time.Date(2026, 10, 17, 13, 0, 0, 123400, time.UTC)
	logged := when.Add(3 * time.Millisecond)
	img := `\Device\HarddiskVolume3\Windows\System32\cmd.exe`
	sid := []byte{1, 2, 0, 0, 0, 0, 0, 16, 0, 0x30, 0, 0, 0, 0, 0, 0} // S-1-16-12288, 2 sub-authorities
	v0 := cat(le32(4242), le64(toFiletime(when)), le32(100), le32(1), u16z(img))
	v2 := cat(le32(4242), le64(toFiletime(when)), le32(100), le32(1), le32(0), u16z(img), le32(0), le32(0), u16z(""), u16z(""))
	v3 := cat(le32(4242), le64(77), le64(toFiletime(when)), le32(100), le64(76), le32(1), le32(0), le32(2), le32(1), sid, u16z(img), le32(0), le32(0), u16z(""), u16z(""))
	for name, data := range map[string][]byte{"v0": v0, "v2": v2, "v3": v3} {
		pid, ppid, created, nt, ok := parseProcStart(data, logged)
		if !ok || pid != 4242 || ppid != 100 || nt != img || !created.Equal(when) {
			t.Errorf("%s: got %d %d %v %q %v", name, pid, ppid, created, nt, ok)
		}
	}
	// An unknown layout keeps the PID and admits it knows nothing else.
	pid, ppid, created, nt, ok := parseProcStart(cat(le32(7), make([]byte, 40)), logged)
	if !ok || pid != 7 || ppid != 0 || !created.IsZero() || nt != "" {
		t.Errorf("unknown layout: %d %d %v %q %v", pid, ppid, created, nt, ok)
	}
	if _, _, _, _, ok := parseProcStart([]byte{1, 2}, logged); ok {
		t.Error("short payload accepted")
	}
}

func TestProcStopLayouts(t *testing.T) {
	when := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	logged := when.Add(time.Hour)
	old := cat(le32(9), le64(toFiletime(when)), le64(toFiletime(logged)), le32(0))
	seq := cat(le32(9), le64(1234), le64(toFiletime(when)), le64(toFiletime(logged)), le32(0))
	for name, data := range map[string][]byte{"v0": old, "v2": seq} {
		if pid, c, ok := parseProcStop(data, logged); !ok || pid != 9 || !c.Equal(when) {
			t.Errorf("%s: %d %v %v", name, pid, c, ok)
		}
	}
}

func TestFiletimeMatchesSyscall(t *testing.T) {
	// syscall.Filetime.Nanoseconds: (ft - 116444736000000000) * 100.
	ft := uint64(133420000000000000)
	if got, want := filetime(ft).UnixNano(), (int64(ft)-116444736000000000)*100; got != want {
		t.Errorf("filetime %d, want %d", got, want)
	}
	if !filetime(0).IsZero() {
		t.Error("zero FILETIME should be zero time")
	}
}

func TestParseTCP(t *testing.T) {
	v4 := cat(le32(321), le32(0), []byte{149, 154, 167, 220}, []byte{192, 168, 1, 5}, be16(443), be16(50123), make([]byte, 24))
	pid, local, remote, ok := parseTCP(false, v4)
	if !ok || pid != 321 || remote != netip.MustParseAddrPort("149.154.167.220:443") || local != netip.MustParseAddrPort("192.168.1.5:50123") {
		t.Errorf("v4: %d %v %v %v", pid, local, remote, ok)
	}
	d6 := netip.MustParseAddr("2606:4700::6810:84e5").As16()
	s6 := netip.MustParseAddr("::1").As16()
	v6 := cat(le32(9), le32(0), d6[:], s6[:], be16(443), be16(60000))
	pid, local, remote, ok = parseTCP(true, v6)
	if !ok || pid != 9 || remote.Addr().String() != "2606:4700::6810:84e5" || remote.Port() != 443 || local.Port() != 60000 {
		t.Errorf("v6: %d %v %v %v", pid, local, remote, ok)
	}
	// An IPv4-mapped IPv6 address comes out as plain IPv4.
	m := netip.MustParseAddr("::ffff:1.2.3.4").As16()
	_, _, remote, _ = parseTCP(true, cat(le32(1), le32(0), m[:], s6[:], be16(80), be16(1)))
	if remote.Addr().String() != "1.2.3.4" {
		t.Errorf("mapped: %v", remote)
	}
	if _, _, _, ok := parseTCP(false, make([]byte, 19)); ok {
		t.Error("short v4 accepted")
	}
}

func TestParseDNS(t *testing.T) {
	data := cat(u16z("API.Telegram.org."), le32(1), le64(0), le32(0),
		u16z("type:  5 edge.example.net;::ffff:149.154.167.220;2001:67c:4e8:f004::9;"))
	name, status, ans, ok := parseDNS(data)
	if !ok || name != "api.telegram.org" || status != 0 || len(ans) != 2 ||
		ans[0].String() != "149.154.167.220" || ans[1].String() != "2001:67c:4e8:f004::9" {
		t.Errorf("got %q %d %v %v", name, status, ans, ok)
	}
	failed := cat(u16z("nope.invalid"), le32(1), le64(0), le32(9003), u16z(""))
	if name, status, ans, ok := parseDNS(failed); !ok || name != "nope.invalid" || status != 9003 || len(ans) != 0 {
		t.Errorf("failed query: %q %d %v %v", name, status, ans, ok)
	}
	if _, _, _, ok := parseDNS([]byte{'a', 0}); ok {
		t.Error("unterminated name accepted")
	}
}

func TestEventIDFilter(t *testing.T) {
	b := eventIDFilter([]uint16{12, 28})
	if len(b) != 8 || b[0] != 1 || binary.LittleEndian.Uint16(b[2:]) != 2 ||
		binary.LittleEndian.Uint16(b[4:]) != 12 || binary.LittleEndian.Uint16(b[6:]) != 28 {
		t.Errorf("filter bytes %v", b)
	}
}

func TestPlausible(t *testing.T) {
	now := time.Now()
	if !plausible(now.Add(-time.Second), now, 5*time.Second) || plausible(now.Add(-time.Minute), now, 5*time.Second) ||
		plausible(time.Time{}, now, time.Hour) || plausible(filetime(1234), now, 100*365*24*time.Hour) {
		t.Error("plausible")
	}
}
