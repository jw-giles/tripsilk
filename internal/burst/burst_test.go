package burst

import (
	"fmt"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func TestSpawnBurst(t *testing.T) {
	d := New(Default)
	var hits int
	for i := 0; i < 100; i++ {
		if _, ok := d.Spawn(`C:\x\claude.exe`, t0.Add(time.Duration(i)*50*time.Millisecond)); ok {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("hits %d, want 1 (then quiet)", hits)
	}
	// After the quiet period it can fire again.
	at := t0.Add(Default.Quiet + time.Minute)
	for i := 0; i < Default.Spawns; i++ {
		if _, ok := d.Spawn(`C:\x\CLAUDE.exe`, at.Add(time.Duration(i)*time.Millisecond)); ok {
			hits++
		}
	}
	if hits != 2 {
		t.Fatalf("hits %d after quiet period, want 2", hits)
	}
}

// A build: many starts, but spread out like real work.
func TestSteadyWorkIsNotABurst(t *testing.T) {
	d := New(Default)
	for i := 0; i < 2000; i++ { // three a second for 11 minutes
		if h, ok := d.Spawn(`C:\x\claude.exe`, t0.Add(time.Duration(i)*333*time.Millisecond)); ok {
			t.Fatalf("steady work flagged: %+v", h)
		}
	}
	for i := 0; i < 500; i++ { // the same few hosts, over and over
		if h, ok := d.Dest(`C:\x\claude.exe`, fmt.Sprintf("host%d.example", i%6), t0.Add(time.Duration(i)*10*time.Millisecond)); ok {
			t.Fatalf("repeat destinations flagged: %+v", h)
		}
	}
}

func TestNewDestinationBurst(t *testing.T) {
	d := New(Default)
	var got Hit
	for i := 0; i < 20; i++ {
		if h, ok := d.Dest(`C:\x\agent.exe`, fmt.Sprintf("site%d.example", i), t0.Add(time.Duration(i)*time.Second)); ok {
			got = h
			break
		}
	}
	if got.Count != Default.Dests || len(got.Recent) != 8 || got.Recent[7] != "site11.example" {
		t.Fatalf("hit %+v", got)
	}
	// Slow exploration (one new site a minute) never trips it.
	d2 := New(Default)
	for i := 0; i < 200; i++ {
		if _, ok := d2.Dest(`C:\x\agent.exe`, fmt.Sprintf("s%d", i), t0.Add(time.Duration(i)*time.Minute)); ok {
			t.Fatal("slow exploration flagged")
		}
	}
}

func TestAgentsCountedSeparatelyAndBounded(t *testing.T) {
	d := New(Default)
	for i := 0; i < Default.Spawns-1; i++ {
		d.Spawn(`C:\a.exe`, t0)
		d.Spawn(`C:\b.exe`, t0)
	}
	if _, ok := d.Spawn(`C:\c.exe`, t0); ok {
		t.Fatal("agents' counts mixed")
	}
	for i := 0; i < maxAgents*3; i++ {
		d.Spawn(fmt.Sprintf(`C:\%d.exe`, i), t0.Add(time.Duration(i)))
	}
	for i := 0; i < maxKnown*3; i++ {
		d.Dest(`C:\z.exe`, fmt.Sprint(i), t0.Add(time.Duration(i)*time.Hour))
	}
	if len(d.agents) > maxAgents || len(d.agents[`c:\z.exe`].known) > maxKnown {
		t.Fatalf("unbounded: %d agents", len(d.agents))
	}
	if _, ok := d.Spawn("", t0); ok {
		t.Fatal("empty agent counted")
	}
}
