package service

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"tripsilk/internal/win"
)

const usageEvery = 10 * time.Second

// Usage is what Tripsilk itself costs the PC, shown in Settings so the
// "light" claim can be checked rather than taken on trust.
type Usage struct {
	CPUPercent  float64 `json:"cpuPercent"`  // share of the whole PC over the last 10 s
	PeakPercent float64 `json:"peakPercent"` // highest 10-second share since start
	MemoryMB    float64 `json:"memoryMB"`    // working set
	DiskMB      float64 `json:"diskMB"`      // settings, history and journal
	Measured    bool    `json:"measured"`
}

type usageState struct {
	last    time.Duration
	lastAt  time.Time
	current Usage
}

func (s *Service) startUsage(ctx context.Context) {
	go s.every(ctx, usageEvery, s.sampleUsage)
}

func (s *Service) sampleUsage() {
	cpu, ws, ok := win.SelfUsage()
	now := time.Now()
	disk := dirSize(s.dataDir)
	s.mu.Lock()
	defer s.mu.Unlock()
	u := &s.us.current
	u.DiskMB = float64(disk) / (1 << 20)
	if !ok {
		return
	}
	u.MemoryMB = float64(ws) / (1 << 20)
	if !s.us.lastAt.IsZero() {
		wall := now.Sub(s.us.lastAt)
		if wall > 0 {
			u.CPUPercent = cpuShare(cpu-s.us.last, wall, runtime.NumCPU())
			if u.CPUPercent > u.PeakPercent {
				u.PeakPercent = u.CPUPercent
			}
			u.Measured = true
		}
	}
	s.us.last, s.us.lastAt = cpu, now
}

// cpuShare converts processor time used over a wall-clock span into a
// percentage of the whole PC (all cores).
func cpuShare(used, wall time.Duration, cores int) float64 {
	if wall <= 0 || cores <= 0 || used < 0 {
		return 0
	}
	return 100 * float64(used) / float64(wall) / float64(cores)
}

// dirSize adds up regular files under dir, not following links.
func dirSize(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}
