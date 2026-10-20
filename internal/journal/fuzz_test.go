package journal

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A journal file can be cut off by a crash or a full disk; reading it back
// must skip the damage, not fail.
func FuzzReadSince(f *testing.F) {
	f.Add([]byte(`{"time":"2026-10-17T13:00:00Z","type":"alert","data":{}}` + "\n"))
	f.Add([]byte(`{"time":"2026-10-17T13:00:00Z","type":"al`))
	f.Add([]byte("\x00\xff\n\n{}\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "events-20261017-130000.000.jsonl"), b, 0o600)
		if _, err := ReadSince(dir, time.Time{}, 10); err != nil {
			t.Fatal(err)
		}
	})
}
