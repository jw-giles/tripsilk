//go:build !windows

package agentguard

import "tripsilk/internal/engine"

func SnapshotProcs() ([]Proc, error) { return nil, engine.ErrUnsupported }
func FillCmdLine(p *Proc)            {}

func StartupEntries() (map[string][]StartupEntry, map[string]bool) {
	return nil, map[string]bool{"all": true}
}
