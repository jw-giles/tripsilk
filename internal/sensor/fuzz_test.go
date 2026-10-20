package sensor

import (
	"testing"
	"time"
)

// Payloads come from Windows, but a parser must never crash or hang on
// bytes it didn't expect. These fuzz targets throw arbitrary input at each.

func FuzzParseProcStart(f *testing.F) {
	now := time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)
	f.Add(cat(le32(1), le64(toFiletime(now)), le32(2), le32(1), u16z(`\Device\x.exe`)))
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		pid, ppid, created, nt, ok := parseProcStart(b, now)
		if ok && len(b) < 4 {
			t.Fatal("ok on short input")
		}
		if !created.IsZero() && !plausible(created, now, 5*time.Second) {
			t.Fatalf("implausible creation time accepted: %v", created)
		}
		_, _, _ = pid, ppid, nt
	})
}

func FuzzParseProcStop(f *testing.F) {
	now := time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)
	f.Add(cat(le32(9), le64(toFiletime(now.Add(-time.Hour)))))
	f.Fuzz(func(t *testing.T, b []byte) { parseProcStop(b, now) })
}

func FuzzParseTCP(f *testing.F) {
	f.Add(true, make([]byte, 44))
	f.Add(false, make([]byte, 20))
	f.Fuzz(func(t *testing.T, v6 bool, b []byte) {
		_, local, remote, ok := parseTCP(v6, b)
		if ok && (!local.Addr().IsValid() || !remote.Addr().IsValid()) {
			t.Fatal("ok with invalid address")
		}
	})
}

func FuzzParseDNS(f *testing.F) {
	f.Add(cat(u16z("a.example.com"), le32(1), le64(0), le32(0), u16z("1.2.3.4;")))
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, b []byte) { parseDNS(b) })
}
