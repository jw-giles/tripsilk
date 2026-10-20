package win

// PSQuote single-quotes a string for safe embedding in a PowerShell script.
// Inside single quotes PowerShell treats everything literally except quote
// characters (ASCII and the typographic variants), which are escaped by
// doubling.
func PSQuote(s string) string {
	out := make([]rune, 0, len(s)+2)
	out = append(out, '\'')
	for _, r := range s {
		if r == '\'' || r == '‘' || r == '’' || r == '‚' || r == '‛' {
			out = append(out, r)
		}
		out = append(out, r)
	}
	return string(append(out, '\''))
}
