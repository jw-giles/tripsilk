package service

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"tripsilk/internal/agentguard"
	"tripsilk/internal/defender"
	"tripsilk/internal/engine"
	"tripsilk/internal/respond"
	"tripsilk/internal/shield"
)

const (
	burstWindow    = 6 * time.Second
	burstThreshold = 40 // distinct user files changed in the window
	burstCooldown  = 2 * time.Minute
	writeSample    = 2 * time.Second
)

type shieldState struct {
	watcher      *shield.Watcher
	burst        *shield.Burst
	folders      []string
	samples      []ioSample
	on           bool
	disconnected bool
	cfa          defender.FolderProtection
}

func (s *Service) startShield(ctx context.Context) {
	folders := shield.UserFolders()
	s.mu.Lock()
	s.sh.burst = shield.NewBurst(burstWindow, burstThreshold, burstCooldown)
	s.sh.folders = folders
	s.mu.Unlock()

	w, watched := shield.Watch(folders, s.onFileChange)
	blocked := respond.OutboundBlocked()
	s.mu.Lock()
	s.sh.watcher = w
	s.sh.on = len(watched) > 0
	s.sh.disconnected = blocked
	s.mu.Unlock()

	go s.every(ctx, writeSample, s.sampleWrites)
	go func() {
		<-ctx.Done()
		if w != nil {
			w.Stop()
		}
	}()
}

// onFileChange feeds the burst detector. A burst triggers a write sample and,
// unless in practice mode, suspends the process writing the most.
func (s *Service) onFileChange(path string) {
	s.mu.Lock()
	b := s.sh.burst
	s.mu.Unlock()
	if b == nil {
		return
	}
	if n := b.Observe(path, time.Now()); n > 0 {
		s.onBurst(n, path)
	}
}

// ioSample is one reading of every process's total bytes written.
type ioSample struct {
	at    time.Time
	bytes map[uint32]uint64
}

const keepSamples = 6 // 12 seconds at one sample every 2 seconds

func (s *Service) sampleWrites() {
	procs, err := agentguard.SnapshotProcs()
	if err != nil {
		return
	}
	pids := make([]uint32, len(procs))
	for i, p := range procs {
		pids[i] = p.PID
	}
	cur, _ := shield.WriteCounters(pids, false)
	s.mu.Lock()
	s.sh.samples = append(s.sh.samples, ioSample{at: time.Now(), bytes: cur})
	if len(s.sh.samples) > keepSamples {
		s.sh.samples = s.sh.samples[len(s.sh.samples)-keepSamples:]
	}
	s.mu.Unlock()
}

// baselineLocked returns the newest sample taken at least one burst window
// before now (so the comparison spans the whole burst), else the oldest.
func (s *Service) baselineLocked(now time.Time) (ioSample, bool) {
	var base ioSample
	found := false
	for _, smp := range s.sh.samples {
		if now.Sub(smp.at) >= burstWindow {
			base, found = smp, true
		}
	}
	if !found && len(s.sh.samples) > 0 {
		return s.sh.samples[0], true
	}
	return base, found
}

func (s *Service) onBurst(n int, samplePath string) {
	now := time.Now()
	procs, _ := agentguard.SnapshotProcs()
	pids := make([]uint32, len(procs))
	created := make(map[uint32]time.Time, len(procs))
	for i, p := range procs {
		pids[i] = p.PID
		created[p.PID] = p.Created
	}
	cur, images := shield.WriteCounters(pids, true)
	s.mu.Lock()
	base, ok := s.baselineLocked(now)
	self := s.selfImage
	s.mu.Unlock()

	// Rank every writer, trusted ones included, so confidence is judged
	// against the whole picture: if Explorer wrote the most, that burst was
	// probably a copy, and the runner-up must not be suspended for it.
	var all, writers []shield.Writer
	if ok {
		// A process missing from the baseline counts from zero only if it
		// started after the baseline was taken.
		isNew := func(pid uint32) bool { c := created[pid]; return !c.IsZero() && c.After(base.at) }
		all = shield.TopWriters(base.bytes, cur, images, isNew, func(pid uint32, img string) bool {
			return strings.EqualFold(img, self)
		})
		for _, w := range all {
			if !shield.Trusted(w.Image) {
				writers = append(writers, w)
			}
		}
	}
	folder := filepath.Dir(samplePath)
	if len(writers) == 0 {
		s.Bus.Publish(engine.Alert{Severity: engine.SevHigh, Source: "shield",
			Title:   "Unusual burst of file changes",
			Summary: fmt.Sprintf("%d of your files changed within seconds, and Tripsilk couldn't tell which program did it.", n),
			Why:     "Ransomware scrambles files this fast. Disconnecting stops it reaching whoever controls it while you check.",
			Do:      "disconnect",
			Detail: fmt.Sprintf("%d files in %s changed in a few seconds, which can mean ransomware. "+
				"Tripsilk couldn't tell which program did it. Check what's running and consider disconnecting from the internet.",
				n, folder),
			Actions: []string{"disconnect"}})
		return
	}

	top := writers[0]
	if !shield.Confident(all) || shield.Trusted(all[0].Image) {
		// No single program clearly did it: name the candidates, suspend nothing.
		var names []string
		for i, w := range writers {
			if i == 3 {
				break
			}
			names = append(names, fmt.Sprintf("%s (%.1f MB)", filepath.Base(w.Image), float64(w.Bytes)/(1<<20)))
		}
		s.Bus.Publish(engine.Alert{Severity: engine.SevCritical, Source: "shield", PID: top.PID, Process: top.Image,
			Title:   "Possible ransomware: unclear which program",
			Summary: fmt.Sprintf("%d of your files changed within seconds; no single program clearly did it.", n),
			Why:     "Ransomware scrambles files this fast. Suspend any program in the list you don't recognize.",
			Do:      "suspend",
			Detail: fmt.Sprintf("%d files in %s changed within seconds. The programs writing the most were %s. "+
				"None stood out clearly, so Tripsilk didn't suspend anything. Suspend any you don't recognize.",
				n, folder, strings.Join(names, ", ")),
			Actions: []string{"suspend", "scan", "disconnect"}})
		return
	}

	s.respondToBurst(top, n, folder)
}

// respondToBurst acts on a confident ransomware-shield hit: contains,
// suspends or only records, by the user's settings, and raises the alert.
func (s *Service) respondToBurst(top shield.Writer, n int, folder string) {
	dry := s.dryRun()
	var cr *containResult
	if dry {
		// Practice: record what containment would have done, so the week
		// of results covers ransomware-shield hits too.
		s.contain(top.PID, top.Image, time.Now())
	} else if s.store.Get().AutoContain {
		// Automatic containment: the whole family, and its internet.
		r := s.contain(top.PID, top.Image, time.Now())
		cr = &r
		dry = r.frozen == 0
	} else {
		s.contain(top.PID, top.Image, time.Now()) // records the practice result
		if _, err := s.suspendOnce(top.PID, top.Image); err != nil {
			dry = true // couldn't suspend: fall back to warning
		}
	}
	a := engine.Alert{Severity: engine.SevCritical, Source: "shield", PID: top.PID, Process: top.Image,
		Title: filepath.Base(top.Image) + " may be ransomware"}
	verb := "Tripsilk suspended it"
	acts := []string{"terminate", "resume", "scan", "disconnect"}
	if dry {
		verb = "Practice mode is on (or the suspend failed), so Tripsilk only logged this"
		acts = []string{"suspend", "scan", "disconnect"}
	}
	a.Detail = fmt.Sprintf("%s changed %d files in %s within seconds while writing %.1f MB, far more than any other program. "+
		"That is how ransomware behaves. %s. If this was something you started on purpose (a backup or a large extract), resume it; "+
		"otherwise scan it, and disconnect from the internet while you check.",
		filepath.Base(top.Image), n, folder, float64(top.Bytes)/(1<<20), verb)
	if cr != nil && cr.frozen > 0 {
		acts = []string{"resumeall", "terminate", "scan", "disconnect"}
		a.Detail += " " + containNote(top.Image, *cr)
	}
	a.Actions = acts
	a.Summary = fmt.Sprintf("%s changed %d of your files within seconds, far more than anything else.", filepath.Base(top.Image), n)
	if dry {
		a.Why = "That's how ransomware behaves. Practice mode is on, so Tripsilk didn't stop it."
		a.Do = "suspend"
	} else {
		a.Why = "That's how ransomware behaves, so Tripsilk froze it. If you started a backup or a big extract, resume it."
		a.Do = "scan"
	}
	s.Bus.Publish(a)
}

// ---- actions ----

// Terminate ends a process for good. Confirmed in the UI before calling.
func (s *Service) Terminate(pid uint32, image string) error {
	if err := respond.CheckTarget(pid, image); err != nil {
		return err
	}
	if s.dryRun() {
		s.note("Dry run: would end", fmt.Sprintf("%s (PID %d)", filepath.Base(image), pid))
		return nil
	}
	if err := respond.Terminate(pid, image); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.suspended, pid)
	s.mu.Unlock()
	s.saveSuspended()
	s.note("Process ended", fmt.Sprintf("%s (PID %d) was ended.", filepath.Base(image), pid))
	return nil
}

// ScanProgram has Defender scan one program.
func (s *Service) ScanProgram(image string) error {
	if image == "" {
		return fmt.Errorf("no program to scan")
	}
	s.note("Scanning with Defender", filepath.Base(image))
	go func() {
		_ = defender.UpdateSignatures()
		err := defender.ScanPath(image)
		if err != nil {
			s.Bus.Publish(engine.Alert{Severity: engine.SevMedium, Source: "defender",
				Title: "Scan failed", Detail: err.Error()})
		} else {
			s.note("Scan finished", filepath.Base(image)+". Any detection appears under Microsoft Defender.")
		}
		s.refreshDefender()
	}()
	return nil
}

// Disconnect blocks all outbound traffic, for a live intrusion.
func (s *Service) Disconnect() error {
	if s.dryRun() {
		s.note("Dry run: would disconnect", "Every program would be blocked from the internet.")
		return nil
	}
	if err := respond.BlockAllOutbound(); err != nil {
		return err
	}
	s.mu.Lock()
	s.sh.disconnected = true
	s.mu.Unlock()
	s.note("Internet disconnected", "Every program is blocked from the internet, including Defender updates. Tripsilk's dashboard keeps working. Use Reconnect when you're sure it's safe.")
	return nil
}

// Reconnect removes the emergency block.
func (s *Service) Reconnect() error {
	if err := respond.UnblockAllOutbound(); err != nil {
		return err
	}
	s.mu.Lock()
	s.sh.disconnected = false
	s.mu.Unlock()
	s.note("Internet restored", "")
	return nil
}

// SetFolderProtection toggles Windows Controlled Folder Access.
func (s *Service) SetFolderProtection(on bool) error {
	if err := defender.SetFolderProtection(on); err != nil {
		return err
	}
	s.mu.Lock()
	s.sh.cfa = defender.GetFolderProtection()
	s.mu.Unlock()
	if on {
		s.note("Folder protection on", "Windows now blocks unapproved programs from changing your Documents, Pictures and other folders.")
	} else {
		s.note("Folder protection off", "")
	}
	return nil
}

func (s *Service) refreshCFA() {
	cfa := defender.GetFolderProtection()
	s.mu.Lock()
	s.sh.cfa = cfa
	s.mu.Unlock()
}
