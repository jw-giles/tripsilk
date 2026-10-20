// Package journal writes Tripsilk's events to disk as JSON Lines: one JSON
// object per line, a format any log tool (jq, Splunk, Elastic, a Python
// script) reads directly. Files rotate at a size limit and the oldest are
// deleted once the folder passes its total cap, so the journal never fills
// the disk.
package journal

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultFileLimit  = 16 << 20  // start a new file after 16 MB
	DefaultTotalLimit = 256 << 20 // keep at most 256 MB in total
	prefix            = "events-"
	suffix            = ".jsonl"
)

// Journal appends records to the current file. Safe for concurrent use.
type Journal struct {
	mu        sync.Mutex
	dir       string
	fileLimit int64
	total     int64
	f         *os.File
	w         *bufio.Writer
	size      int64
	written   uint64
	errs      uint64
	lastErr   string
	now       func() time.Time
}

// Open creates dir if needed. Limits of 0 use the defaults.
func Open(dir string, fileLimit, totalLimit int64) (*Journal, error) {
	if fileLimit <= 0 {
		fileLimit = DefaultFileLimit
	}
	if totalLimit <= 0 {
		totalLimit = DefaultTotalLimit
	}
	if totalLimit < fileLimit {
		totalLimit = fileLimit
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Journal{dir: dir, fileLimit: fileLimit, total: totalLimit, now: time.Now}, nil
}

// Dir is where the files are.
func (j *Journal) Dir() string { return j.dir }

// Record is one line. Type says what Data holds ("proc_start", "alert", ...).
type Record struct {
	Time time.Time `json:"time"`
	Type string    `json:"type"`
	Data any       `json:"data"`
}

// Write appends one record. Errors are counted, not returned: the journal
// must never stop detection.
func (j *Journal) Write(typ string, data any) {
	line, err := json.Marshal(Record{Time: j.now().UTC(), Type: typ, Data: data})
	if err != nil {
		j.fail(err)
		return
	}
	line = append(line, '\n')
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil || j.size+int64(len(line)) > j.fileLimit {
		if err := j.rotateLocked(); err != nil {
			j.errs++
			j.lastErr = err.Error()
			return
		}
	}
	n, err := j.w.Write(line)
	j.size += int64(n)
	if err != nil {
		j.errs++
		j.lastErr = err.Error()
		return
	}
	j.written++
}

func (j *Journal) fail(err error) {
	j.mu.Lock()
	j.errs++
	j.lastErr = err.Error()
	j.mu.Unlock()
}

// Flush writes buffered lines to disk. Called on a timer and at shutdown.
func (j *Journal) Flush() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.w == nil {
		return nil
	}
	return j.w.Flush()
}

// Close flushes and closes the current file.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.closeLocked()
}

func (j *Journal) closeLocked() error {
	if j.f == nil {
		return nil
	}
	err := j.w.Flush()
	if cerr := j.f.Close(); err == nil {
		err = cerr
	}
	j.f, j.w = nil, nil
	return err
}

func (j *Journal) rotateLocked() error {
	_ = j.closeLocked()
	name := filepath.Join(j.dir, prefix+j.now().UTC().Format("20060102-150405.000")+suffix)
	// O_EXCL: never append to (or follow) a file something else put here.
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		name = strings.TrimSuffix(name, suffix) + fmt.Sprintf("-%d", j.written) + suffix
		f, err = os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	}
	if err != nil {
		return err
	}
	j.f, j.w, j.size = f, bufio.NewWriterSize(f, 64<<10), 0
	j.pruneLocked(name)
	return nil
}

// pruneLocked deletes the oldest journal files until the folder fits the
// total cap. The file just opened is never deleted.
func (j *Journal) pruneLocked(keep string) {
	files := Files(j.dir)
	var sum int64
	sizes := make([]int64, len(files))
	for i, f := range files {
		if fi, err := os.Lstat(f); err == nil && fi.Mode().IsRegular() {
			sizes[i] = fi.Size()
			sum += fi.Size()
		}
	}
	for i := 0; i < len(files) && sum+j.fileLimit > j.total; i++ {
		if files[i] == keep {
			continue
		}
		if os.Remove(files[i]) == nil {
			sum -= sizes[i]
		}
	}
}

// Files lists journal files oldest first (names sort by time).
func Files(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(n, prefix) && strings.HasSuffix(n, suffix) {
			out = append(out, filepath.Join(dir, n))
		}
	}
	sort.Strings(out)
	return out
}

// Stats is shown in Settings.
type Stats struct {
	Dir     string `json:"dir"`
	Written uint64 `json:"written"`
	Errors  uint64 `json:"errors"`
	LastErr string `json:"lastError,omitempty"`
	Bytes   int64  `json:"bytes"`
	Files   int    `json:"files"`
}

func (j *Journal) Stats() Stats {
	j.mu.Lock()
	st := Stats{Dir: j.dir, Written: j.written, Errors: j.errs, LastErr: j.lastErr}
	j.mu.Unlock()
	for _, f := range Files(j.dir) {
		if fi, err := os.Lstat(f); err == nil {
			st.Bytes += fi.Size()
			st.Files++
		}
	}
	return st
}

// ReadSince returns records newer than t from all files, oldest first, up to
// max records (the newest ones). Lines that don't parse are skipped.
func ReadSince(dir string, t time.Time, max int) ([]json.RawMessage, error) {
	var out []json.RawMessage
	files := Files(dir)
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			var head struct {
				Time time.Time `json:"time"`
			}
			b := sc.Bytes()
			if json.Unmarshal(b, &head) != nil || !head.Time.After(t) {
				continue
			}
			out = append(out, append(json.RawMessage{}, b...))
			if max > 0 && len(out) > max {
				out = out[1:]
			}
		}
		f.Close()
	}
	return out, nil
}
