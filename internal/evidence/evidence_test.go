package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSHA256AndCache(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.exe")
	os.WriteFile(p, []byte("abc"), 0o600)
	h := NewHasher(2)
	sum, err := h.SHA256(p)
	if err != nil || sum != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sum %s %v", sum, err)
	}
	// A changed file is re-hashed.
	os.WriteFile(p, []byte("abcd"), 0o600)
	os.Chtimes(p, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	if sum2, _ := h.SHA256(p); sum2 == sum {
		t.Fatal("stale cache")
	}
	for i := 0; i < 5; i++ {
		q := filepath.Join(t.TempDir(), "y.exe")
		os.WriteFile(q, []byte{byte(i)}, 0o600)
		h.SHA256(q)
	}
	if len(h.cache) > 2 {
		t.Fatalf("cache grew to %d", len(h.cache))
	}
	if _, err := h.SHA256(""); err == nil {
		t.Error("empty path hashed")
	}
	if _, err := h.SHA256(t.TempDir()); err == nil {
		t.Error("directory hashed")
	}
}

func TestChain(t *testing.T) {
	t0 := time.Now()
	table := map[uint32]Proc{
		1:  {PID: 1, PPID: 0, Image: "explorer.exe", Created: t0},
		2:  {PID: 2, PPID: 1, Image: "claude.exe", Created: t0.Add(time.Second)},
		3:  {PID: 3, PPID: 2, Image: "cmd.exe", Created: t0.Add(2 * time.Second)},
		9:  {PID: 9, PPID: 8, Image: "a.exe", Created: t0},
		8:  {PID: 8, PPID: 7, Image: "recycled.exe", Created: t0.Add(time.Hour)},
		20: {PID: 20, PPID: 21}, 21: {PID: 21, PPID: 20},
	}
	c := Chain(table, 3, 10)
	if len(c) != 3 || c[0].Image != "cmd.exe" || c[2].Image != "explorer.exe" {
		t.Errorf("chain %v", c)
	}
	if c := Chain(table, 9, 10); len(c) != 1 {
		t.Errorf("recycled parent followed: %v", c)
	}
	if c := Chain(table, 3, 2); len(c) != 2 {
		t.Errorf("depth ignored: %v", c)
	}
	if c := Chain(table, 20, 10); len(c) != 2 {
		t.Errorf("loop: %v", c)
	}
	if Chain(table, 99, 10) != nil {
		t.Error("unknown pid")
	}
}

func TestHashReReadWhenSizeAndTimeArePutBack(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.exe")
	os.WriteFile(p, []byte("good"), 0o600)
	h := NewHasher(8)
	first, err := h.SHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	// Same size, same time, different bytes.
	os.WriteFile(p, []byte("evil"), 0o600)
	os.Chtimes(p, fi.ModTime(), fi.ModTime())
	if sum, _ := h.SHA256(p); sum != first {
		t.Fatal("within the window the cache is expected to be reused")
	}
	h.mu.Lock()
	for k, e := range h.cache {
		e.at = e.at.Add(-hashKeep - time.Second)
		h.cache[k] = e
	}
	h.mu.Unlock()
	if _, ok := h.Cached(p); ok {
		t.Fatal("an old digest must not be offered as current")
	}
	if sum, _ := h.SHA256(p); sum == first {
		t.Fatal("an old digest was reused after the window")
	}
}
