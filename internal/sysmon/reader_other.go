//go:build !windows

package sysmon

import "errors"

var ErrNotInstalled = errors.New("Sysmon isn't installed")

func Latest() (uint64, error)                              { return 0, ErrNotInstalled }
func Since(after uint64, max int) ([]Event, uint64, error) { return nil, after, ErrNotInstalled }
