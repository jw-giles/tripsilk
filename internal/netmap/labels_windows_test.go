package netmap

import (
	"net"
	"testing"
	"time"
)

func TestLearnedLabelsExpire(t *testing.T) {
	r := NewResolver()
	r.Learn("api.anthropic.com", []net.IP{net.ParseIP("160.79.104.10")})
	if r.Lookup(net.ParseIP("160.79.104.10")) == "" {
		t.Fatal("learned label missing")
	}
	r.mu.Lock()
	r.pruneLabels(time.Now().Add(labelKeep + time.Minute))
	r.mu.Unlock()
	if l := r.Lookup(net.ParseIP("160.79.104.10")); l != "" {
		t.Fatalf("stale label kept: %q", l)
	}
}
