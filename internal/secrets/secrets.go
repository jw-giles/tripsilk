// Package secrets is Tripsilk's key watch. It knows where common credentials
// live (SSH keys, cloud CLI logins, browser password and cookie stores,
// crypto wallets) and decides which reads of them deserve an alert.
//
// The files are the user's own; Tripsilk never opens or copies them. Detection
// uses Windows object-access auditing: Tripsilk adds a read audit rule to each
// file and the Security log then names every process that reads it. Each
// file has normal owners (chrome.exe reading Chrome's passwords), which are
// ignored. What remains is judged here:
//
//   - one program reading from two or more different stores: the pattern of
//     password-stealing malware (critical)
//   - an AI agent, or a program it started, reading one (high)
//   - one browser reading another browser's store: usually an import (low)
//   - any other program (medium, with an Allow choice)
//
// This file is pure logic and runs on any OS.
package secrets

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"tripsilk/internal/canary"
)

// Root is where a pattern is anchored.
type Root int

const (
	Home         Root = iota // %USERPROFILE%
	AppData                  // %APPDATA% (Roaming)
	LocalAppData             // %LOCALAPPDATA%
)

// Pattern is a glob under a root, written with forward slashes.
type Pattern struct {
	Root Root
	Glob string
}

// Kind is one credential store.
type Kind struct {
	ID    string
	Label string // shown to the user: "your <Label>"
	Group string // kinds in the same group may read each other's (browser import)
	Paths []Pattern
	// Skip: base-name globs under Paths that are not secrets (public keys).
	Skip []string
	// Owners: programs that normally read this store. An entry containing
	// a backslash matches anywhere in the lowercased full path (an install
	// folder); otherwise it is a glob on the lowercased base name.
	Owners []string
}

func chromium(id, label, dir string, owners ...string) Kind {
	var ps []Pattern
	for _, f := range []string{"Login Data", "Web Data", "Cookies", "Network/Cookies"} {
		ps = append(ps, Pattern{LocalAppData, dir + "/User Data/*/" + f})
	}
	return Kind{ID: id, Label: label, Group: "browser", Paths: ps, Owners: owners}
}

// Catalog is every store Tripsilk knows about.
var Catalog = []Kind{
	{ID: "ssh", Label: "SSH keys",
		Paths:  []Pattern{{Home, ".ssh/*"}},
		Skip:   []string{"*.pub", "known_hosts*", "config", "authorized_keys", "environment", "*.log"},
		Owners: []string{"ssh.exe", "ssh-agent.exe", "ssh-add.exe", "ssh-keygen.exe", "scp.exe", "sftp.exe", "sshd.exe"}},
	{ID: "aws", Label: "AWS credentials",
		Paths:  []Pattern{{Home, ".aws/credentials"}},
		Owners: []string{"aws.exe", `\amazon\awscliv2\`}},
	{ID: "azure", Label: "Azure sign-in",
		Paths:  []Pattern{{Home, ".azure/msal_token_cache.*"}, {Home, ".azure/accessTokens.json"}, {Home, ".azure/service_principal_entries.*"}},
		Owners: []string{`\microsoft sdks\azure\cli2\`, "az.exe"}},
	{ID: "gcloud", Label: "Google Cloud credentials",
		Paths: []Pattern{{AppData, "gcloud/credentials.db"}, {AppData, "gcloud/access_tokens.db"},
			{AppData, "gcloud/application_default_credentials.json"}, {AppData, "gcloud/legacy_credentials/*/adc.json"}},
		Owners: []string{`\google\cloud sdk\`, "gcloud.exe"}},
	{ID: "kube", Label: "Kubernetes config",
		Paths:  []Pattern{{Home, ".kube/config"}},
		Owners: []string{"kubectl.exe", "helm.exe", "k9s.exe", "docker desktop.exe", "com.docker.backend.exe"}},
	{ID: "docker", Label: "Docker logins",
		Paths: []Pattern{{Home, ".docker/config.json"}},
		Owners: []string{"docker.exe", "docker-credential-*.exe", "com.docker.*.exe", "docker desktop.exe",
			"docker-compose.exe"}},
	{ID: "git", Label: "saved Git passwords",
		Paths:  []Pattern{{Home, ".git-credentials"}},
		Owners: []string{"git.exe", "git-credential-*.exe", "git-remote-http*.exe"}},
	{ID: "gh", Label: "GitHub CLI login",
		Paths:  []Pattern{{AppData, "GitHub CLI/hosts.yml"}},
		Owners: []string{"gh.exe"}},
	chromium("chrome", "Chrome passwords and cookies", "Google/Chrome", "chrome.exe", `\google\chrome\application\`),
	chromium("edge", "Edge passwords and cookies", "Microsoft/Edge", "msedge.exe", `\microsoft\edge\application\`),
	chromium("brave", "Brave passwords and cookies", "BraveSoftware/Brave-Browser", "brave.exe", `\bravesoftware\brave-browser\application\`),
	{ID: "firefox", Label: "Firefox passwords and cookies", Group: "browser",
		Paths: []Pattern{{AppData, "Mozilla/Firefox/Profiles/*/logins.json"}, {AppData, "Mozilla/Firefox/Profiles/*/key4.db"},
			{AppData, "Mozilla/Firefox/Profiles/*/cookies.sqlite"}},
		Owners: []string{"firefox.exe", `\mozilla firefox\`}},
	{ID: "wallet", Label: "crypto wallets",
		Paths: []Pattern{{AppData, "Electrum/wallets/*"}, {AppData, "Exodus/exodus.wallet/*"},
			{AppData, "Bitcoin/wallet.dat"}, {AppData, "Bitcoin/wallets/*/wallet.dat"}},
		Owners: []string{"electrum*.exe", "exodus.exe", "bitcoin-qt.exe", "bitcoind.exe"}},
}

// KindByID returns a catalog entry.
func KindByID(id string) (Kind, bool) {
	for _, k := range Catalog {
		if k.ID == id {
			return k, true
		}
	}
	return Kind{}, false
}

// Env holds the root folders. Empty roots are skipped.
type Env struct{ Home, AppData, LocalAppData string }

func (e Env) root(r Root) string {
	switch r {
	case Home:
		return e.Home
	case AppData:
		return e.AppData
	case LocalAppData:
		return e.LocalAppData
	}
	return ""
}

// Item is one credential file found on this PC.
type Item struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

// MaxItems caps discovery so a folder full of files can't make Tripsilk add
// thousands of audit rules.
const MaxItems = 300

// Discover finds the credential files that exist now. It only lists
// directories and stats files; it never reads them.
func Discover(env Env) []Item {
	var out []Item
	seen := map[string]bool{}
	for _, k := range Catalog {
		for _, p := range k.Paths {
			root := env.root(p.Root)
			if root == "" {
				continue
			}
			matches, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(p.Glob)))
			sort.Strings(matches)
			for _, m := range matches {
				if skipped(k, m) || seen[strings.ToLower(m)] {
					continue
				}
				if fi, err := os.Stat(m); err != nil || !fi.Mode().IsRegular() {
					continue
				}
				seen[strings.ToLower(m)] = true
				out = append(out, Item{Kind: k.ID, Path: m})
				if len(out) >= MaxItems {
					return out
				}
			}
		}
	}
	return out
}

func skipped(k Kind, path string) bool {
	b := strings.ToLower(filepath.Base(path))
	for _, s := range k.Skip {
		if ok, _ := filepath.Match(s, b); ok {
			return true
		}
	}
	return false
}

func baseOf(image string) string {
	b := strings.ToLower(image)
	if i := strings.LastIndexAny(b, `\/`); i >= 0 {
		b = b[i+1:]
	}
	return b
}

// IsOwner reports whether image normally reads this kind of store.
func IsOwner(k Kind, image string) bool {
	full := strings.ToLower(strings.ReplaceAll(image, "/", `\`))
	base := baseOf(image)
	for _, o := range k.Owners {
		if strings.Contains(o, `\`) {
			if strings.Contains(full, o) {
				return true
			}
		} else if ok, _ := filepath.Match(o, base); ok {
			return true
		}
	}
	return false
}

// alwaysIgnored: Windows components that open files to scan, index or show
// them. Explorer reads files to draw previews and properties when you browse
// a folder, so it is ignored too (a limit noted in the README).
func alwaysIgnored(image string) bool {
	return canary.IsSystemReader(image) || baseOf(image) == "explorer.exe"
}

// Read is one audited read of a watched file.
type Read struct {
	Path  string
	Image string
	PID   uint32
	When  time.Time
	Agent string // image of the AI agent this process descends from, if any
}

// Level grades a finding.
type Level int

const (
	Import  Level = iota // a browser reading another browser's store
	Unknown              // an unrecognized program
	Agent                // an AI agent or something it started
	Stealer              // one program reading several different stores
)

// Finding is a read worth telling the user about.
type Finding struct {
	Level Level
	Kind  Kind
	Kinds []string // for Pattern: labels of every store it read recently
	Read  Read
}

const (
	patternWindow = 2 * time.Minute
	repeatAfter   = 30 * time.Minute
	importRepeat  = 6 * time.Hour
)

// Analyzer turns audited reads into findings. Safe for concurrent use.
type Analyzer struct {
	mu      sync.Mutex
	index   map[string]string // lowercase path -> kind ID
	recent  map[string]map[string]time.Time
	alerted map[string]time.Time
	allowed func(kind, image string) bool
}

// NewAnalyzer builds an analyzer. allowed reports user approvals; it may be nil.
func NewAnalyzer(allowed func(kind, image string) bool) *Analyzer {
	return &Analyzer{index: map[string]string{}, recent: map[string]map[string]time.Time{},
		alerted: map[string]time.Time{}, allowed: allowed}
}

// SetItems replaces the set of watched files.
func (a *Analyzer) SetItems(items []Item) {
	idx := make(map[string]string, len(items))
	for _, it := range items {
		idx[strings.ToLower(filepath.Clean(it.Path))] = it.Kind
	}
	a.mu.Lock()
	a.index = idx
	a.mu.Unlock()
}

// Watched reports whether a path is a watched credential file.
func (a *Analyzer) Watched(path string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.index[strings.ToLower(filepath.Clean(path))]
	return ok
}

// Observe judges one read. It returns nil when the read is normal, allowed,
// or already reported recently.
func (a *Analyzer) Observe(r Read) *Finding {
	a.mu.Lock()
	defer a.mu.Unlock()
	id, ok := a.index[strings.ToLower(filepath.Clean(r.Path))]
	if !ok || r.Image == "" || r.PID <= 4 {
		return nil
	}
	k, _ := KindByID(id)
	if IsOwner(k, r.Image) || alwaysIgnored(r.Image) {
		return nil
	}
	if a.allowed != nil && a.allowed(k.ID, r.Image) {
		return nil
	}
	img := strings.ToLower(r.Image)
	a.prune(r.When)

	if k.Group != "" {
		for _, other := range Catalog {
			if other.ID != k.ID && other.Group == k.Group && IsOwner(other, r.Image) {
				if a.once("imp|"+img+"|"+k.ID, r.When, importRepeat) {
					return &Finding{Level: Import, Kind: k, Read: r}
				}
				return nil
			}
		}
	}

	kinds := a.recent[img]
	if kinds == nil {
		kinds = map[string]time.Time{}
		a.recent[img] = kinds
	}
	kinds[k.ID] = r.When
	if len(kinds) >= 2 {
		if a.once("pat|"+img, r.When, repeatAfter) {
			var labels []string
			for _, c := range Catalog {
				if _, ok := kinds[c.ID]; ok {
					labels = append(labels, c.Label)
				}
			}
			return &Finding{Level: Stealer, Kind: k, Kinds: labels, Read: r}
		}
		return nil
	}
	lvl := Unknown
	if r.Agent != "" {
		lvl = Agent
	}
	if a.once("one|"+img+"|"+k.ID, r.When, repeatAfter) {
		return &Finding{Level: lvl, Kind: k, Read: r}
	}
	return nil
}

// once reports whether key hasn't fired within d, and records it.
func (a *Analyzer) once(key string, at time.Time, d time.Duration) bool {
	if last, ok := a.alerted[key]; ok && at.Sub(last) < d && at.Sub(last) > -d {
		return false
	}
	a.alerted[key] = at
	return true
}

func (a *Analyzer) prune(now time.Time) {
	for img, kinds := range a.recent {
		for id, t := range kinds {
			if now.Sub(t) > patternWindow {
				delete(kinds, id)
			}
		}
		if len(kinds) == 0 {
			delete(a.recent, img)
		}
	}
	for k, t := range a.alerted {
		if now.Sub(t) > importRepeat {
			delete(a.alerted, k)
		}
	}
}
