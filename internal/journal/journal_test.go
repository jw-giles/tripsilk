package journal

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestWriteAndReadBack(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Second)
	j.Write("proc_start", map[string]any{"pid": 42, "image": `C:\x\y.exe`})
	j.Write("alert", map[string]any{"title": "hi"})
	if err := j.Flush(); err != nil {
		t.Fatal(err)
	}
	recs, err := ReadSince(dir, start, 0)
	if err != nil || len(recs) != 2 {
		t.Fatalf("got %d records, %v", len(recs), err)
	}
	var r struct {
		Type string         `json:"type"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recs[0], &r); err != nil || r.Type != "proc_start" || r.Data["image"] != `C:\x\y.exe` {
		t.Errorf("first record %s (%v)", recs[0], err)
	}
	if st := j.Stats(); st.Written != 2 || st.Files != 1 || st.Errors != 0 {
		t.Errorf("stats %+v", st)
	}
	j.Close()
}

func TestRotationAndCap(t *testing.T) {
	dir := t.TempDir()
	j, _ := Open(dir, 1000, 3000)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	j.now = func() time.Time { clock = clock.Add(time.Second); return clock }
	pad := make([]byte, 200)
	for i := range pad {
		pad[i] = 'x'
	}
	for i := 0; i < 100; i++ {
		j.Write("x", map[string]any{"i": i, "pad": string(pad)})
	}
	j.Close()
	files := Files(dir)
	var total int64
	for _, f := range files {
		fi, _ := os.Stat(f)
		total += fi.Size()
		if fi.Size() > 1000 {
			t.Errorf("%s is %d bytes, over the file limit", f, fi.Size())
		}
	}
	if total > 3000 {
		t.Errorf("journal holds %d bytes, over the 3000 cap", total)
	}
	if len(files) < 2 {
		t.Errorf("expected rotation, got %d files", len(files))
	}
	// The newest records survive pruning.
	recs, _ := ReadSince(dir, time.Time{}, 0)
	var last struct {
		Data struct{ I int } `json:"data"`
	}
	json.Unmarshal(recs[len(recs)-1], &last)
	if last.Data.I != 99 {
		t.Errorf("last record %d, want 99", last.Data.I)
	}
	if recs2, _ := ReadSince(dir, time.Time{}, 3); len(recs2) != 3 {
		t.Errorf("max 3 returned %d", len(recs2))
	}
}

func TestIgnoresOtherFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/notes.txt", []byte("hello"), 0o600)
	os.Mkdir(dir+"/events-dir.jsonl", 0o700)
	if f := Files(dir); len(f) != 0 {
		t.Errorf("listed %v", f)
	}
}
