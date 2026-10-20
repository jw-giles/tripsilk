package eventlog

import "strings"

// stripNUL: a NUL inside alert text (from a program's command line) would
// end the event's text early.
func stripNUL(s string) string { return strings.ReplaceAll(s, "\x00", "\\0") }
