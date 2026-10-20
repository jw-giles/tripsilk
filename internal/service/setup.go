package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tripsilk/internal/engine"
	"tripsilk/internal/win"
)

// tripLineText is what someone who opens the file reads. A program that
// opens it has already tripped it.
const tripLineText = "This file is a Tripsilk trip line. Nothing on this PC should open or change it.\r\n" +
	"If you opened it yourself, that's fine: mark the alert as handled in Tripsilk.\r\n"

// CreateTripline makes a trip-line file in a believable place and starts
// watching it, for the first-run setup. The name looks like ordinary old
// paperwork, not like passwords: decoy credentials are deliberately left
// out (a build that touched credential stores was flagged by Defender).
// Synced folders (OneDrive) open files to sync them, so the file goes in
// the profile folder instead when Documents is synced.
func (s *Service) CreateTripline() (string, error) {
	base := win.Documents()
	if base == "" || strings.Contains(strings.ToLower(base), "onedrive") {
		base = win.Home()
	}
	if base == "" {
		return "", errors.New("couldn't find your Documents or profile folder")
	}
	dir := filepath.Join(base, "Archive")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for i := 0; i < 10; i++ {
		name := "old-projects-index.txt"
		if i > 0 {
			name = fmt.Sprintf("old-projects-index-%d.txt", i+1)
		}
		path := filepath.Join(dir, name)
		for _, w := range s.reg.List() {
			if strings.EqualFold(w.Path, path) {
				return path, nil // already a trip line
			}
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if errors.Is(err, os.ErrExist) {
			continue // someone's real file: never take it over
		}
		if err != nil {
			return "", err
		}
		_, werr := f.WriteString(tripLineText)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return "", werr
		}
		if err := s.AddBait(path); err != nil && !errors.Is(err, engine.ErrUnsupported) {
			return path, err
		}
		return path, nil
	}
	return "", errors.New("couldn't find a free name for the trip line in " + dir)
}

// FinishSetup records that the first-run setup is done (or skipped).
func (s *Service) FinishSetup() error {
	return s.store.Update(func(c *engine.Config) { c.SetupDone = true })
}
