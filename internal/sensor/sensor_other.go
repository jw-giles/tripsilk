//go:build !windows || !(amd64 || arm64)

package sensor

import "errors"

// errUnsupported: event tracing needs 64-bit Windows.
var errUnsupported = errors.New("event tracing needs 64-bit Windows")

type Sensor struct{}

func New(name string) *Sensor                { return &Sensor{} }
func (s *Sensor) Start(fn func(Event)) error { return errUnsupported }
func (s *Sensor) Stop()                      {}
func (s *Sensor) Running() bool              { return false }
func StopSession(name string)                {}
func (s *Sensor) Stats() Stats               { return Stats{Error: errUnsupported.Error()} }
