package win

import "testing"

func TestPSQuote(t *testing.T) {
	cases := map[string]string{
		`C:\x\a.txt`:     `'C:\x\a.txt'`,
		`it's`:           `'it''s'`,
		"smart\u2019q":   "'smart\u2019\u2019q'",
		`$(evil) ; calc`: `'$(evil) ; calc'`,
	}
	for in, want := range cases {
		if got := PSQuote(in); got != want {
			t.Errorf("PSQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
