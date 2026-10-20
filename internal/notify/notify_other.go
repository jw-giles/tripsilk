//go:build !windows

package notify

import "tripsilk/internal/engine"

func Toast(title, body string) error                 { return engine.ErrUnsupported }
func SetStartAtSignIn(on bool, workDir string) error { return engine.ErrUnsupported }
func StartsAtSignIn() bool                           { return false }
