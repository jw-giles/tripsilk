//go:build !windows

package eventlog

import (
	"errors"

	"tripsilk/internal/engine"
)

var errOS = errors.New("the Windows Event Log is only on Windows")

func Register() error   { return errOS }
func Unregister() error { return nil }

type Writer struct{}

func Open() (*Writer, error)                 { return nil, errOS }
func (w *Writer) Write(a engine.Alert) error { return errOS }
func (w *Writer) Close()                     {}
