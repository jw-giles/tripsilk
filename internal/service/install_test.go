package service

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstalledUnder(t *testing.T) {
	pf := filepath.Join(string(filepath.Separator)+"pf", "Program Files")
	if runtime.GOOS == "windows" {
		pf = `C:\Program Files`
	}
	in := filepath.Join(pf, "Tripsilk", "Tripsilk.exe")
	cases := []struct {
		exe  string
		want bool
	}{
		{in, true},
		{filepath.Join(pf+" (x86)", "Tripsilk", "Tripsilk.exe"), false}, // a sibling with a longer name
		{filepath.Join(pf, "..", "Tripsilk", "build", "bin", "Tripsilk.exe"), false},
		{pf, false},
		{"", false},
	}
	for _, c := range cases {
		if got := installedUnder(c.exe, pf); got != c.want {
			t.Errorf("installedUnder(%q) = %v, want %v", c.exe, got, c.want)
		}
	}
	if installedUnder(in, "") {
		t.Error("unknown Program Files folder must not count as installed")
	}
}
