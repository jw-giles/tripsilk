package netmap

import (
	"testing"
	"time"
)

func TestMatchProvider(t *testing.T) {
	cases := map[string]string{
		"api.openai.com":                          "OpenAI",
		"API.ANTHROPIC.COM.":                      "Anthropic",
		"foo.openrouter.ai":                       "OpenRouter",
		"bedrock-runtime.us-east-1.amazonaws.com": "AWS Bedrock",
		"example.com":                             "",
		"notopenai.example.com":                   "",
	}
	for host, want := range cases {
		if got := MatchProvider(host); got != want {
			t.Errorf("MatchProvider(%q)=%q want %q", host, got, want)
		}
	}
}

func TestMatchLocalRuntime(t *testing.T) {
	if MatchLocalRuntime(`C:\Users\x\AppData\Local\Programs\Ollama\ollama.exe`) != "Ollama" {
		t.Error("ollama not matched")
	}
	if MatchLocalRuntime(`/usr/bin/firefox`) != "" {
		t.Error("false positive")
	}
}

func TestTrackerNewAndForget(t *testing.T) {
	tr := NewTracker()
	f := Flow{PID: 10, Image: `C:\a.exe`, Provider: "OpenAI", Remote: "1.2.3.4:443"}
	if _, isNew := tr.Observe(f); !isNew {
		t.Fatal("first sighting should be new")
	}
	if _, isNew := tr.Observe(f); isNew {
		t.Fatal("second sighting should not be new")
	}
	if len(tr.Snapshot()) != 1 {
		t.Fatal("dedup failed")
	}
	// Age it out.
	old := f
	old.LastSeen = time.Now().Add(-time.Hour)
	tr.flows[old.key()] = old
	if n := tr.Forget(time.Minute); n != 1 {
		t.Fatalf("forget removed %d", n)
	}
}

func TestParseDNSCache(t *testing.T) {
	out := []byte(`[{"Entry":"api.openai.com","Data":"162.159.140.245"},{"Entry":"api.anthropic.com","Data":"2607:6bc0::10"},{"Entry":"example.com","Data":"93.184.216.34"},{"Entry":"api.openai.com","Data":"not-an-ip"}]`)
	m := ParseDNSCache(out)
	if len(m) != 2 || m["162.159.140.245"] != "OpenAI" || m["2607:6bc0::10"] != "Anthropic" {
		t.Fatalf("got %v", m)
	}
	if one := ParseDNSCache([]byte(`{"Entry":"api.x.ai","Data":"1.2.3.4"}`)); one["1.2.3.4"] != "xAI" {
		t.Fatalf("single object: %v", one)
	}
	if ParseDNSCache([]byte("garbage")) != nil {
		t.Fatal("bad output must return nil so the old cache is kept")
	}
}

func TestParseDNSHosts(t *testing.T) {
	m := ParseDNSHosts([]byte(`[{"Entry":"API.Steampowered.com.","Data":"23.1.2.3"},{"Entry":"x","Data":"bad"}]`))
	if len(m) != 1 || m["23.1.2.3"] != "api.steampowered.com" {
		t.Fatalf("%v", m)
	}
}
