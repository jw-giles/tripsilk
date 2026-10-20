//go:build !windows

package shield

// Watcher is a stub off Windows.
type Watcher struct{}

func UserFolders() []string                                          { return nil }
func Watch(folders []string, emit func(string)) (*Watcher, []string) { return &Watcher{}, nil }
func (w *Watcher) Stop()                                             {}
func WriteCounters(pids []uint32, withImages bool) (map[uint32]uint64, map[uint32]string) {
	return map[uint32]uint64{}, map[uint32]string{}
}
