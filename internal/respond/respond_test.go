package respond

import (
	"errors"
	"os"
	"testing"
)

func TestCheckTarget(t *testing.T) {
	if !errors.Is(CheckTarget(500, `C:\Windows\System32\lsass.exe`), ErrProtected) {
		t.Error("lsass must be protected")
	}
	if !errors.Is(CheckTarget(4, "System"), ErrProtected) {
		t.Error("PID 4 must be protected")
	}
	if CheckTarget(uint32(os.Getpid()), `C:\x\tripsilk.exe`) == nil {
		t.Error("self must be refused")
	}
	if CheckTarget(1234, "") == nil {
		t.Error("unknown image must be refused")
	}
	if err := CheckTarget(1234, `C:\Users\j\agent.exe`); err != nil {
		t.Errorf("ordinary process refused: %v", err)
	}
}

func TestRuleNameStable(t *testing.T) {
	if RuleName(`C:\A\B.exe`) != RuleName(`c:\a\b.exe`) {
		t.Error("rule name must be case-insensitive")
	}
}

func TestOwnRuleKnowsOldAndNewNames(t *testing.T) {
	if img, ok := OwnRule(RuleName(`C:\X\Bad.exe`)); !ok || img != `c:\x\bad.exe` {
		t.Fatalf("new rule: %q %v", img, ok)
	}
	if img, ok := OwnRule("aWall block: c:\\x\\old.exe"); !ok || img != `c:\x\old.exe` {
		t.Fatalf("aWall-era rule must still be recognized: %q %v", img, ok)
	}
	if _, ok := OwnRule("Some other rule"); ok {
		t.Fatal("rules Tripsilk didn't make must be refused")
	}
}
