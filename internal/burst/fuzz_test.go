package burst

import (
	"testing"
	"time"
)

func FuzzDetector(f *testing.F) {
	f.Add("a.exe", "x.example", int64(0), true)
	f.Fuzz(func(t *testing.T, agent, dest string, ns int64, spawn bool) {
		d := New(Limits{Spawns: 2, SpawnWindow: time.Second, Dests: 2, DestWindow: time.Second, Quiet: time.Second})
		at := time.Unix(0, ns)
		for i := 0; i < 4; i++ {
			if spawn {
				d.Spawn(agent, at)
			} else {
				d.Dest(agent, dest, at)
			}
		}
	})
}
