//go:build !windows

package canary

import (
	"time"

	"tripsilk/internal/engine"
)

type Watcher struct{}

func NewWatcher(reg *Registry, emit func(Event)) *Watcher { return &Watcher{} }
func (w *Watcher) Sync() error                            { return engine.ErrUnsupported }
func (w *Watcher) Stop()                                  {}

func EnableReadAuditing(paths []string) error { return engine.ErrUnsupported }
func AuditPolicyOn() error                    { return engine.ErrUnsupported }

func AddReadAudit(paths []string) (map[string]string, error) { return nil, engine.ErrUnsupported }

func RemoveReadAudit(paths []string) (map[string]string, error) { return nil, engine.ErrUnsupported }

func AuditReads(since time.Time) ([]Access, error) { return nil, engine.ErrUnsupported }

func ReadEvents(reg *Registry, since time.Time, selfImage string) ([]Event, error) {
	return nil, engine.ErrUnsupported
}
