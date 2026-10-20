package channels

import (
	"strings"
	"testing"
)

// Names come from DNS answers any program can trigger. Matching must never
// panic, and a match must really be the listed domain or under it.
func FuzzMatch(f *testing.F) {
	for _, s := range []string{"api.telegram.org", "notdiscord.com", "x..ngrok.app.", "", ".", "ÄPI.TELEGRAM.ORG"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, d string) {
		c, ok := Match(d)
		if !ok {
			return
		}
		n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		for _, base := range c.Domains {
			if n == base || strings.HasSuffix(n, "."+base) {
				return
			}
		}
		t.Fatalf("%q matched %s without a listed domain", d, c.ID)
	})
}
