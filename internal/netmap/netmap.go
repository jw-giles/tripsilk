// Package netmap builds the "AI traffic map": which processes on this machine
// are talking to LLM API endpoints, and which local model runtimes are
// running. It is read-only observation — it opens no connections and changes
// nothing.
//
// Two signals:
//   - Remote endpoints: the active TCP table is joined to DNS so a connection
//     to an LLM provider's address is attributed to the owning PID and image.
//   - Local runtimes: processes whose image name matches a known local-model
//     server (ollama, llama.cpp, lm studio, ...), which never touch the
//     network and so would be missed by the endpoint signal alone.
package netmap

import (
	"encoding/json"
	"net"
	"sort"
	"strings"
	"time"
)

// Provider maps a hostname suffix to a human label.
type Provider struct {
	Suffix string
	Label  string
}

// Providers is the endpoint catalog. Suffixes are matched case-insensitively
// against the resolved hostname of a connection's remote address.
var Providers = []Provider{
	{"api.openai.com", "OpenAI"},
	{"api.anthropic.com", "Anthropic"},
	{"generativelanguage.googleapis.com", "Google Gemini"},
	{"aiplatform.googleapis.com", "Google Vertex AI"},
	{"api.mistral.ai", "Mistral"},
	{"api.cohere.ai", "Cohere"},
	{"api.cohere.com", "Cohere"},
	{"openrouter.ai", "OpenRouter"},
	{"api.groq.com", "Groq"},
	{"api.deepseek.com", "DeepSeek"},
	{"api.together.xyz", "Together"},
	{"api.perplexity.ai", "Perplexity"},
	{"api.x.ai", "xAI"},
	{"bedrock-runtime", "AWS Bedrock"}, // regional host prefix
	{"inference.ai.azure.com", "Azure AI"},
	{"openai.azure.com", "Azure OpenAI"},
	{"huggingface.co", "Hugging Face"},
	{"replicate.com", "Replicate"},
}

// LocalRuntimes maps a lowercase image base name to a label.
var LocalRuntimes = map[string]string{
	"ollama.exe":                "Ollama",
	"ollama app.exe":            "Ollama",
	"llama-server.exe":          "llama.cpp",
	"llama-cli.exe":             "llama.cpp",
	"lmstudio.exe":              "LM Studio",
	"lm studio.exe":             "LM Studio",
	"jan.exe":                   "Jan",
	"koboldcpp.exe":             "KoboldCpp",
	"text-generation-webui.exe": "Oobabooga",
	"localai.exe":               "LocalAI",
	"gpt4all.exe":               "GPT4All",
}

// MatchProvider returns the provider label for a hostname, or "" if none.
func MatchProvider(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range Providers {
		if strings.Contains(host, p.Suffix) {
			return p.Label
		}
	}
	return ""
}

// MatchLocalRuntime returns the runtime label for an image path, or "".
func MatchLocalRuntime(imagePath string) string {
	base := imagePath
	if i := strings.LastIndexAny(base, `\/`); i >= 0 {
		base = base[i+1:]
	}
	return LocalRuntimes[strings.ToLower(base)]
}

// Flow is one process-to-provider observation.
type Flow struct {
	PID       uint32    `json:"pid"`
	Image     string    `json:"image"`
	Provider  string    `json:"provider"`
	Remote    string    `json:"remote"` // "host:port" or "ip:port"
	Local     bool      `json:"local"`  // true for a local model runtime
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// key identifies a flow for deduplication across scans.
func (f Flow) key() string {
	return f.Image + "|" + f.Provider + "|" + f.Remote
}

// Tracker accumulates flows across repeated scans, preserving FirstSeen.
type Tracker struct {
	flows map[string]Flow
}

func NewTracker() *Tracker { return &Tracker{flows: map[string]Flow{}} }

// Observe records a flow, merging with any prior sighting.
func (t *Tracker) Observe(f Flow) (Flow, bool) {
	now := time.Now()
	if f.LastSeen.IsZero() {
		f.LastSeen = now
	}
	k := f.key()
	if prev, ok := t.flows[k]; ok {
		prev.LastSeen = f.LastSeen
		t.flows[k] = prev
		return prev, false // not new
	}
	if f.FirstSeen.IsZero() {
		f.FirstSeen = now
	}
	t.flows[k] = f
	return f, true // newly seen
}

// Snapshot returns current flows, newest activity first.
func (t *Tracker) Snapshot() []Flow {
	out := make([]Flow, 0, len(t.flows))
	for _, f := range t.flows {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// Forget drops flows not seen since the cutoff, so the map reflects live
// activity. Returns the number removed.
func (t *Tracker) Forget(olderThan time.Duration) int {
	cutoff := time.Now().Add(-olderThan)
	n := 0
	for k, f := range t.flows {
		if f.LastSeen.Before(cutoff) {
			delete(t.flows, k)
			n++
		}
	}
	return n
}

// dnsCacheScript lists A (1) and AAAA (28) records from the DNS client cache.
const dnsCacheScript = `@(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | Select-Object Entry,Data) | ConvertTo-Json -Compress`

// ParseDNSCache maps cached addresses of known AI providers to labels.
// Returns nil when the output can't be parsed.
func ParseDNSCache(out []byte) map[string]string {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return map[string]string{}
	}
	if strings.HasPrefix(s, "{") {
		s = "[" + s + "]"
	}
	var rows []struct{ Entry, Data string }
	if json.Unmarshal([]byte(s), &rows) != nil {
		return nil
	}
	m := map[string]string{}
	for _, r := range rows {
		label := MatchProvider(r.Entry)
		ip := net.ParseIP(strings.TrimSpace(r.Data))
		if label != "" && ip != nil {
			m[ip.String()] = label
		}
	}
	return m
}

// ParseDNSHosts maps every cached address to the hostname that resolved to
// it. Returns nil when the output can't be parsed.
func ParseDNSHosts(out []byte) map[string]string {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return map[string]string{}
	}
	if strings.HasPrefix(s, "{") {
		s = "[" + s + "]"
	}
	var rows []struct{ Entry, Data string }
	if json.Unmarshal([]byte(s), &rows) != nil {
		return nil
	}
	m := map[string]string{}
	for _, r := range rows {
		ip := net.ParseIP(strings.TrimSpace(r.Data))
		if ip != nil && r.Entry != "" {
			m[ip.String()] = strings.TrimSuffix(strings.ToLower(r.Entry), ".")
		}
	}
	return m
}

// LiveConn is one current connection, for the all-traffic view.
type LiveConn struct {
	PID  uint32
	IP   string
	Port uint16
	Host string // "" when the DNS cache has no name for it
	AI   string // AI provider label, "" otherwise
}

// Listener is a program accepting incoming TCP connections.
type Listener struct {
	PID     uint32 `json:"pid"`
	Image   string `json:"image"`
	Port    uint16 `json:"port"`
	Addr    string `json:"addr"`
	Exposed bool   `json:"exposed"` // reachable from other machines (not loopback-only)
}
