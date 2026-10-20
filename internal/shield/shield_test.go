package shield

import (
	"fmt"
	"testing"
	"time"
)

func TestBurstFiresOnDistinctFilesOnly(t *testing.T) {
	b := NewBurst(10*time.Second, 30, time.Minute)
	t0 := time.Now()
	// One file saved over and over is normal (an editor autosaving).
	for i := 0; i < 100; i++ {
		if b.Observe(`C:\Users\j\Documents\notes.txt`, t0.Add(time.Duration(i)*time.Millisecond)) != 0 {
			t.Fatal("repeated changes to one file must not fire")
		}
	}
	// Many different files in seconds is the ransomware pattern.
	fired := 0
	for i := 0; i < 40; i++ {
		if n := b.Observe(fmt.Sprintf(`C:\Users\j\Documents\f%d.docx`, i), t0.Add(time.Second+time.Duration(i)*10*time.Millisecond)); n > 0 {
			fired = n
		}
	}
	if fired < 30 {
		t.Fatalf("burst of distinct files should fire, got %d", fired)
	}
	// Cooldown: the same burst continuing doesn't fire again immediately.
	if b.Observe(`C:\Users\j\Documents\more.docx`, t0.Add(2*time.Second)) != 0 {
		t.Fatal("cooldown not applied")
	}
}

func TestBurstWindowSlides(t *testing.T) {
	b := NewBurst(time.Second, 5, 0)
	t0 := time.Now()
	for i := 0; i < 4; i++ {
		b.Observe(fmt.Sprintf("a%d", i), t0)
	}
	// Spread out: the old events fall out of the window.
	if b.Observe("late", t0.Add(5*time.Second)) != 0 {
		t.Fatal("events outside the window must not count")
	}
}

func TestTopWriters(t *testing.T) {
	prev := map[uint32]uint64{10: 1000, 20: 500, 30: 9000}
	cur := map[uint32]uint64{10: 900_000, 20: 600, 30: 50_000_000, 40: 2_000_000}
	images := map[uint32]string{10: `C:\x\odd.exe`, 20: `C:\x\idle.exe`, 30: `C:\Windows\explorer.exe`, 40: `C:\x\new.exe`}
	isNew := func(pid uint32) bool { return pid == 40 }
	ws := TopWriters(prev, cur, images, isNew, func(pid uint32, img string) bool { return Trusted(img) })
	if len(ws) != 3 || ws[0].PID != 40 || ws[1].PID != 10 {
		t.Fatalf("trusted explorer excluded, newcomer counted from zero: %+v", ws)
	}
	// An old process missing from the baseline must not count its lifetime total.
	ws = TopWriters(prev, cur, images, func(uint32) bool { return false }, nil)
	for _, w := range ws {
		if w.PID == 40 {
			t.Fatal("old process absent from baseline was counted from zero")
		}
	}
	// Counter going backwards means a reused PID: ignore it.
	if got := TopWriters(map[uint32]uint64{5: 100}, map[uint32]uint64{5: 50}, nil, nil, nil); len(got) != 0 {
		t.Fatal("counter reset must be ignored")
	}
}

func TestConfident(t *testing.T) {
	mb := uint64(MinSuspendBytes)
	if !Confident([]Writer{{Bytes: 50 * mb}, {Bytes: 10 * mb}}) {
		t.Error("clear dominance should be confident")
	}
	if Confident([]Writer{{Bytes: 50 * mb}, {Bytes: 30 * mb}}) {
		t.Error("two heavy writers: not confident which one")
	}
	if Confident([]Writer{{Bytes: mb / 2}}) {
		t.Error("tiny writes should not justify a suspend")
	}
	if Confident(nil) {
		t.Error("no writers: not confident")
	}
}
