//go:build !windows

package respond

import "tripsilk/internal/engine"

func Suspend(pid uint32, expectedImage string) error   { return engine.ErrUnsupported }
func Resume(pid uint32, expectedImage string) error    { return engine.ErrUnsupported }
func Block(image string) (string, error)               { return "", engine.ErrUnsupported }
func Unblock(ruleName string) error                    { return engine.ErrUnsupported }
func Terminate(pid uint32, expectedImage string) error { return engine.ErrUnsupported }
func BlockAllOutbound() error                          { return engine.ErrUnsupported }
func UnblockAllOutbound() error                        { return engine.ErrUnsupported }
func OutboundBlocked() bool                            { return false }
