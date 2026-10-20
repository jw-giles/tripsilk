// Package evidence gathers what a specialist needs to check an alert
// independently: the program file's SHA-256 (to look up on VirusTotal or in
// their own tools), and the chain of programs that started it.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// MaxHashSize: larger files are not hashed (it would hold the alert up).
const MaxHashSize = 256 << 20

// Hasher hashes program files, caching by path, size and modification time
// so a program that alerts repeatedly is read once.
type Hasher struct {
	mu       sync.Mutex
	cache    map[string]entry
	max      int
	inflight map[string]bool
}

type entry struct {
	size  int64
	mod   time.Time
	sum   string
	using time.Time
	at    time.Time // when the file was hashed
}

// hashKeep bounds how long a digest is reused. A program that can rewrite a
// file can also restore its size and time, so the file is re-read after
// this even when both match.
const hashKeep = 10 * time.Minute

func (e entry) fresh(fi os.FileInfo, now time.Time) bool {
	return e.size == fi.Size() && e.mod.Equal(fi.ModTime()) && now.Sub(e.at) < hashKeep
}

func NewHasher(max int) *Hasher {
	return &Hasher{cache: map[string]entry{}, max: max, inflight: map[string]bool{}}
}

// HashLater hashes path in the background unless that is already under way.
func (h *Hasher) HashLater(path string) {
	key := strings.ToLower(path)
	h.mu.Lock()
	if h.inflight[key] {
		h.mu.Unlock()
		return
	}
	h.inflight[key] = true
	h.mu.Unlock()
	go func() {
		_, _ = h.SHA256(path)
		h.mu.Lock()
		delete(h.inflight, key)
		h.mu.Unlock()
	}()
}

var errTooBig = errors.New("file too large to hash")

// SHA256 returns the hex digest of the file at path.
func (h *Hasher) SHA256(path string) (string, error) {
	if path == "" || path == "System" {
		return "", errors.New("no file")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	if fi.Size() > MaxHashSize {
		return "", errTooBig
	}
	key := strings.ToLower(path)
	h.mu.Lock()
	if e, ok := h.cache[key]; ok && e.fresh(fi, time.Now()) {
		e.using = time.Now()
		h.cache[key] = e
		h.mu.Unlock()
		return e.sum, nil
	}
	h.mu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	d := sha256.New()
	if _, err := io.Copy(d, io.LimitReader(f, MaxHashSize+1)); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(d.Sum(nil))

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.cache) >= h.max {
		var oldK string
		var oldT time.Time
		for k, e := range h.cache {
			if oldK == "" || e.using.Before(oldT) {
				oldK, oldT = k, e.using
			}
		}
		delete(h.cache, oldK)
	}
	h.cache[key] = entry{size: fi.Size(), mod: fi.ModTime(), sum: sum, using: time.Now(), at: time.Now()}
	return sum, nil
}

// Cached returns a digest already computed for the file as it is now.
func (h *Hasher) Cached(path string) (string, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.cache[strings.ToLower(path)]
	if !ok || !e.fresh(fi, time.Now()) {
		return "", false
	}
	return e.sum, true
}

// Proc is the minimum the chain needs about a process.
type Proc struct {
	PID     uint32
	PPID    uint32
	Image   string
	Created time.Time
}

// Link is one step in a parent chain, child first.
type Link struct {
	PID   uint32 `json:"pid"`
	Image string `json:"image"`
}

// Chain walks parents from pid through table, child first, at most depth
// links. A parent created after its child is a recycled PID and ends it.
func Chain(table map[uint32]Proc, pid uint32, depth int) []Link {
	var out []Link
	cur, ok := table[pid]
	if !ok {
		return nil
	}
	seen := map[uint32]bool{}
	for len(out) < depth && !seen[cur.PID] {
		seen[cur.PID] = true
		out = append(out, Link{PID: cur.PID, Image: cur.Image})
		p, ok := table[cur.PPID]
		if !ok || cur.PPID == 0 || cur.PPID == cur.PID {
			break
		}
		if !p.Created.IsZero() && !cur.Created.IsZero() && cur.Created.Before(p.Created) {
			break
		}
		cur = p
	}
	return out
}
