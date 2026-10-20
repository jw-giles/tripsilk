//go:build windows

package canary

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"tripsilk/internal/win"
)

const (
	fileListDirectory = 0x0001
	notifyFlags       = 0x00000001 | 0x00000008 | 0x00000010 // FILE_NAME, SIZE, LAST_WRITE

)

// Watcher runs one blocking ReadDirectoryChangesW loop per directory that
// holds bait files. Events for files not in the registry are ignored.
type Watcher struct {
	reg     *Registry
	emit    func(Event)
	mu      sync.Mutex
	handles map[string]syscall.Handle // dir (lowercase) -> handle
	stopped bool
}

func NewWatcher(reg *Registry, emit func(Event)) *Watcher {
	return &Watcher{reg: reg, emit: emit, handles: map[string]syscall.Handle{}}
}

// Sync starts watchers for any new bait directories. Call after Add.
func (w *Watcher) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return nil
	}
	var firstErr error
	for _, dir := range w.reg.Dirs() {
		k := strings.ToLower(dir)
		if _, ok := w.handles[k]; ok {
			continue
		}
		h, err := openDir(dir)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("watch %s: %w", dir, err)
			}
			continue
		}
		w.handles[k] = h
		go w.loop(dir, h)
	}
	return firstErr
}

// Stop closes all directory handles, which ends the watch loops.
func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = true
	for k, h := range w.handles {
		syscall.CancelIoEx(h, nil)
		syscall.CloseHandle(h)
		delete(w.handles, k)
	}
}

func openDir(dir string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	return syscall.CreateFile(p, fileListDirectory,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

func (w *Watcher) loop(dir string, h syscall.Handle) {
	buf := make([]byte, 64*1024)
	for {
		var n uint32
		err := syscall.ReadDirectoryChanges(h, &buf[0], uint32(len(buf)), false,
			notifyFlags, &n, nil, 0)
		if err != nil {
			// Handle closed or folder gone: forget it so a later Sync can
			// watch the folder again instead of skipping a dead watch.
			w.mu.Lock()
			if cur, ok := w.handles[strings.ToLower(dir)]; ok && cur == h {
				delete(w.handles, strings.ToLower(dir))
				syscall.CloseHandle(h)
			}
			w.mu.Unlock()
			return
		}
		if n == 0 {
			continue // overflow; next call resumes
		}
		w.parse(dir, buf[:n])
	}
}

// parse walks FILE_NOTIFY_INFORMATION records. Events in one buffer are
// coalesced per path, so an editor's save-over (remove + add, or a rename
// onto the path) reports once as Replaced instead of as a deletion.
func (w *Watcher) parse(dir string, buf []byte) {
	type rec struct {
		path  string
		kinds []uint32
	}
	var order []string
	seen := map[string]*rec{}
	off := 0
	for off+12 <= len(buf) {
		next := *(*uint32)(unsafe.Pointer(&buf[off]))
		action := *(*uint32)(unsafe.Pointer(&buf[off+4]))
		nameLen := int(*(*uint32)(unsafe.Pointer(&buf[off+8])))
		if off+12+nameLen > len(buf) {
			break
		}
		u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[off+12])), nameLen/2)
		path := filepath.Join(dir, syscall.UTF16ToString(u16))
		if w.reg.Has(path) {
			k := strings.ToLower(path)
			r, ok := seen[k]
			if !ok {
				r = &rec{path: path}
				seen[k] = r
				order = append(order, k)
			}
			r.kinds = append(r.kinds, action)
		}
		if next == 0 {
			break
		}
		off += int(next)
	}
	for _, k := range order {
		r := seen[k]
		if kind := Coalesce(r.kinds); kind != "" {
			w.emit(Event{Path: r.path, Kind: kind, When: time.Now()})
		}
	}
}

// ---- Read detection via object-access auditing (admin, opt-in) ----

// AuditPolicyOn turns on File System success auditing. Only files that carry
// an audit rule produce events, so this alone logs nothing new.
func AuditPolicyOn() error {
	out, err := win.Run(20*time.Second, "auditpol", "/set",
		"/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}", "/success:enable")
	if err != nil {
		return fmt.Errorf("auditpol: %s (run Tripsilk as administrator)", strings.TrimSpace(string(out)))
	}
	return nil
}

// EnableReadAuditing turns on File System success auditing and adds a read
// audit rule (Everyone, ReadData) to each bait file. It changes system audit
// policy, so the UI only calls it when the user switches read detection on.
func EnableReadAuditing(paths []string) error {
	if err := AuditPolicyOn(); err != nil {
		return err
	}
	failed, err := AddReadAudit(paths)
	if err != nil {
		return err
	}
	for p, why := range failed {
		return fmt.Errorf("audit rule on %s: %s", p, why)
	}
	return nil
}

// auditBatch keeps each PowerShell command line well under Windows' limit.
const auditBatch = 40

// AddReadAudit adds the read audit rule to each file. It returns the files
// it couldn't change, with the reason (often: the file is open in a program
// that locks it). Adding a rule a file already has is harmless.
func AddReadAudit(paths []string) (map[string]string, error) {
	return auditRule(paths, "AddAuditRule")
}

// RemoveReadAudit removes the rule AddReadAudit added, leaving any other
// audit rules on the file alone.
func RemoveReadAudit(paths []string) (map[string]string, error) {
	return auditRule(paths, "RemoveAuditRuleSpecific")
}

func auditRule(paths []string, method string) (map[string]string, error) {
	failed := map[string]string{}
	for i := 0; i < len(paths); i += auditBatch {
		end := i + auditBatch
		if end > len(paths) {
			end = len(paths)
		}
		quoted := make([]string, 0, end-i)
		for _, p := range paths[i:end] {
			quoted = append(quoted, win.PSQuote(p))
		}
		script := `$r=New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','ReadData','None','None','Success'); ` +
			`$bad=@(); foreach($p in @(` + strings.Join(quoted, ",") + `)){ try { ` +
			`$a=Get-Acl -LiteralPath $p -Audit -ErrorAction Stop; [void]$a.` + method + `($r); ` +
			`Set-Acl -LiteralPath $p -AclObject $a -ErrorAction Stop } catch { ` +
			`$bad+=[pscustomobject]@{Path=$p;Error=$_.Exception.Message} } }; ConvertTo-Json -Compress -InputObject @($bad)`
		out, err := win.PowerShell(2*time.Minute, script)
		if err != nil {
			return failed, fmt.Errorf("audit rules: %s", strings.TrimSpace(string(out)))
		}
		var bad []struct{ Path, Error string }
		if s := strings.TrimSpace(string(out)); s != "" {
			if err := json.Unmarshal([]byte(s), &bad); err != nil {
				return failed, fmt.Errorf("audit rules: unexpected output %q", s)
			}
		}
		for _, b := range bad {
			failed[b.Path] = strings.TrimSpace(b.Error)
		}
	}
	return failed, nil
}

// AuditReads returns every audited file read (event 4663) since `since`.
func AuditReads(since time.Time) ([]Access, error) {
	script := `$s=[datetime]::Parse(` + win.PSQuote(since.UTC().Format(time.RFC3339)) + `).ToLocalTime(); ` +
		`@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663;StartTime=$s} -ErrorAction SilentlyContinue | ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }; [pscustomobject]@{Object=$d['ObjectName'];Proc=$d['ProcessName'];Pid=$d['ProcessId'];Time=$_.TimeCreated.ToUniversalTime().ToString('o')} }) | ConvertTo-Json -Compress`
	out, err := win.PowerShell(60*time.Second, script)
	if err != nil {
		return nil, fmt.Errorf("read Security log: %s", strings.TrimSpace(string(out)))
	}
	return ParseAccesses(out)
}

// ReadEvents returns 4663 read events on watched files since `since`.
// Tripsilk's own process is excluded.
func ReadEvents(reg *Registry, since time.Time, selfImage string) ([]Event, error) {
	acc, err := AuditReads(since)
	if err != nil {
		return nil, err
	}
	return BaitReads(acc, reg, selfImage), nil
}
