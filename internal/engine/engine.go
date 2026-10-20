// Package engine holds the cross-platform core: the alert bus, the alert
// history ring buffer, and persisted configuration (allowlist, settings).
package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"tripsilk/internal/evidence"
	"tripsilk/internal/win"
)

// ErrUnsupported is returned by platform features on unsupported OSes.
var ErrUnsupported = errors.New("not supported on this platform")

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Alert is one detection, shown in the UI feed.
type Alert struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Severity Severity  `json:"severity"`
	Source   string    `json:"source"` // "canary", "netmap", "defender", "system"
	Title    string    `json:"title"`
	// Summary and Why are the plain version: one sentence on what
	// happened, one on why it matters, for someone who isn't technical.
	// Do is the one recommended action (one of Actions). Detail holds the
	// technical account and is shown under "Show evidence".
	Summary string `json:"summary,omitempty"`
	Why     string `json:"why,omitempty"`
	Do      string `json:"do,omitempty"`
	Detail  string `json:"detail"`
	PID     uint32 `json:"pid,omitempty"`
	Process string `json:"process,omitempty"` // full image path when known
	Child   string `json:"child,omitempty"`   // for agent spawn alerts: the launched program's name
	Service string `json:"service,omitempty"` // for rule alerts: the AI service outside the rule
	Key     string `json:"key,omitempty"`     // for key watch alerts: the credential store's ID
	Channel string `json:"channel,omitempty"` // for control-channel alerts: the channel's ID
	Dest    string `json:"dest,omitempty"`    // for internet-lock alerts: the place off the list
	// Actions the UI may offer for this alert ("suspend", "block", "allow").
	Actions []string `json:"actions,omitempty"`
	// Evidence lets a specialist check the alert independently.
	Evidence *Evidence `json:"evidence,omitempty"`
}

// Evidence is the hard detail behind an alert.
type Evidence struct {
	SHA256      string          `json:"sha256,omitempty"`
	HashNote    string          `json:"hashNote,omitempty"` // why there's no hash
	Chain       []evidence.Link `json:"chain,omitempty"`    // the program, then what started it
	Destination string          `json:"destination,omitempty"`
}

func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Bus fans alerts out to subscribers and keeps a bounded history.
type Bus struct {
	mu      sync.Mutex
	history []Alert
	max     int
	subs    []func(Alert)
	enrich  func(*Alert)
}

// SetEnrich installs a function that adds evidence to each alert before it
// is stored or sent. It must not block on locks a publisher may hold.
func (b *Bus) SetEnrich(fn func(*Alert)) {
	b.mu.Lock()
	b.enrich = fn
	b.mu.Unlock()
}

func NewBus(max int) *Bus { return &Bus{max: max} }

func (b *Bus) Subscribe(fn func(Alert)) {
	b.mu.Lock()
	b.subs = append(b.subs, fn)
	b.mu.Unlock()
}

func (b *Bus) Publish(a Alert) {
	if a.ID == "" {
		a.ID = NewID()
	}
	if a.Time.IsZero() {
		a.Time = time.Now()
	}
	b.mu.Lock()
	enrich := b.enrich
	b.mu.Unlock()
	if enrich != nil {
		enrich(&a)
	}
	b.mu.Lock()
	b.history = append(b.history, a)
	if len(b.history) > b.max {
		b.history = b.history[len(b.history)-b.max:]
	}
	subs := append([]func(Alert){}, b.subs...)
	b.mu.Unlock()
	for _, fn := range subs {
		fn(a)
	}
}

// History returns alerts newest first.
func (b *Bus) History() []Alert {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Alert, len(b.history))
	for i, a := range b.history {
		out[len(b.history)-1-i] = a
	}
	return out
}

// Config is persisted as JSON in the data directory.
type Config struct {
	// AllowedProcesses: lowercase full image paths the user has approved to
	// talk to AI endpoints without alerting.
	AllowedProcesses []string `json:"allowedProcesses"`
	// BaitFiles: user-designated canary files, re-watched on start.
	BaitFiles []string `json:"baitFiles"`
	// FirewallRules: rule names we created, so we can remove them.
	FirewallRules []string `json:"firewallRules"`
	DryRun        bool     `json:"dryRun"`       // when true, responses are logged, not performed
	ReadAuditing  bool     `json:"readAuditing"` // user opted into 4663 read detection
	MuteToasts    bool     `json:"muteToasts"`   // Windows notifications off (default on)
	// AgentChildAllow: agent image (lowercase path) -> child image names
	// (lowercase base names) the user has approved for that agent.
	AgentChildAllow map[string][]string `json:"agentChildAllow"`
	// ServiceRules: app image (lowercase path) -> the only AI services it
	// may use. Apps without an entry are unrestricted.
	ServiceRules map[string][]string `json:"serviceRules"`
	// Suspended: processes Tripsilk froze, so a restart doesn't orphan them.
	Suspended []SuspendedRecord `json:"suspended"`
	// KeyWatch: the user turned on watching passwords and keys.
	KeyWatch bool `json:"keyWatch"`
	// KeyWatchPaths: files Tripsilk added a read audit rule to, so turning key
	// watch off can remove exactly those rules.
	KeyWatchPaths []string `json:"keyWatchPaths"`
	// KeyAllow: credential store ID -> programs (lowercase paths) the user
	// approved to read it. ID "*" approves every store (a backup program).
	KeyAllow map[string][]string `json:"keyAllow"`
	// ChannelAllow: program (lowercase path) -> control channels (IDs from
	// package channels) the user approved it to reach, e.g. their own
	// Telegram bot script.
	ChannelAllow map[string][]string `json:"channelAllow"`
	// AutoContain: freeze and cut off a program on its own when it touches
	// a trip line or acts like ransomware. Off until the user turns it on;
	// until then Tripsilk records what it would have done.
	AutoContain bool `json:"autoContain"`
	// WouldFreeze: what automatic containment would have frozen while it was
	// off (newest last, at most 50), so the user can judge a week of it
	// before turning it on.
	WouldFreeze []WouldFreeze `json:"wouldFreeze"`
	// SetupDone: the first-run setup was finished or skipped.
	SetupDone bool `json:"setupDone"`
	// DestUsed: agent (lowercase path) -> the places its programs have
	// reached (organizations, or address networks when no name is known),
	// learned as it works. DestAllow: agents whose internet is locked to a
	// list; reaching anything else freezes the agent (in practice mode,
	// records that it would have).
	DestUsed map[string][]string `json:"destUsed"`
	// EventLogCopy: copy alerts to the Windows Event Log (Application log,
	// source Tripsilk). Off by default.
	EventLogCopy bool                `json:"eventLogCopy"`
	DestAllow    map[string][]string `json:"destAllow"`
}

// maxDests bounds each agent's learned list: past it, new places are still
// checked against a lock but no longer learned.
const maxDests = 300

type WouldFreeze struct {
	Time  time.Time `json:"time"`
	Image string    `json:"image"`
	Tree  int       `json:"tree"` // programs in its family
}

type SuspendedRecord struct {
	PID   uint32 `json:"pid"`
	Image string `json:"image"`
}

// Store guards Config and writes it atomically.
type Store struct {
	mu   sync.Mutex
	path string
	cfg  Config
	disk []byte // what Tripsilk last read or wrote, to notice outside edits
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "config.json")}
	data, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(data, &s.cfg); err != nil {
			return nil, err
		}
		s.disk = data
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *Store) Get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.copyLocked()
}

// copyLocked deep-copies the config. Caller holds s.mu.
func (s *Store) copyLocked() Config {
	c := s.cfg
	c.AllowedProcesses = append([]string{}, s.cfg.AllowedProcesses...)
	c.BaitFiles = append([]string{}, s.cfg.BaitFiles...)
	c.FirewallRules = append([]string{}, s.cfg.FirewallRules...)
	c.Suspended = append([]SuspendedRecord{}, s.cfg.Suspended...)
	c.ServiceRules = map[string][]string{}
	for k, v := range s.cfg.ServiceRules {
		c.ServiceRules[k] = append([]string{}, v...)
	}
	c.AgentChildAllow = copyLists(s.cfg.AgentChildAllow)
	c.KeyWatchPaths = append([]string{}, s.cfg.KeyWatchPaths...)
	c.KeyAllow = copyLists(s.cfg.KeyAllow)
	c.ChannelAllow = copyLists(s.cfg.ChannelAllow)
	c.WouldFreeze = append([]WouldFreeze{}, s.cfg.WouldFreeze...)
	c.DestUsed = copyLists(s.cfg.DestUsed)
	c.DestAllow = copyLists(s.cfg.DestAllow)
	return c
}

func copyLists(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = append([]string{}, v...)
	}
	return out
}

// Update changes the config and saves it. The change takes effect only if
// the save succeeds, so what Tripsilk acts on always matches what's on disk:
// a removed approval can't silently come back at the next start.
func (s *Store) Update(fn func(*Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.copyLocked()
	fn(&c)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(s.path, data); err != nil {
		return err
	}
	s.cfg = c
	s.disk = data
	return nil
}

// updateErr is Update for a change that can refuse: when fn returns an
// error nothing is saved.
func (s *Store) updateErr(fn func(*Config) error) error {
	var ferr error
	err := s.Update(func(c *Config) {
		probe := *c
		probe.DestAllow = copyLists(c.DestAllow)
		if ferr = fn(&probe); ferr == nil {
			*c = probe
		}
	})
	if ferr != nil {
		return ferr
	}
	return err
}

// Fresh reports whether no settings file existed when the store opened:
// a first run.
func (s *Store) Fresh() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disk == nil
}

// Verify checks that the settings file still holds what Tripsilk wrote. If
// something else changed or deleted it, Verify writes Tripsilk's settings back
// and reports true: a program editing a security tool's allow lists is
// trying to hide.
func (s *Store) Verify() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	switch {
	case err == nil && bytes.Equal(data, s.disk):
		return false, nil
	case errors.Is(err, os.ErrNotExist) && s.disk == nil:
		return false, nil // never saved yet
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return false, err
	}
	out, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return true, err
	}
	if err := WriteFileAtomic(s.path, out); err != nil {
		return true, err
	}
	s.disk = out
	return true, nil
}

func (s *Store) IsAllowed(image string) bool {
	image = strings.ToLower(image)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.cfg.AllowedProcesses {
		if p == image {
			return true
		}
	}
	return false
}

func (s *Store) Allow(image string) error {
	image = strings.ToLower(image)
	if image == "" {
		return errors.New("empty process path")
	}
	return s.Update(func(c *Config) {
		for _, p := range c.AllowedProcesses {
			if p == image {
				return
			}
		}
		c.AllowedProcesses = append(c.AllowedProcesses, image)
	})
}

func (s *Store) Disallow(image string) error {
	image = strings.ToLower(image)
	return s.Update(func(c *Config) {
		out := c.AllowedProcesses[:0]
		for _, p := range c.AllowedProcesses {
			if p != image {
				out = append(out, p)
			}
		}
		c.AllowedProcesses = out
	})
}

// DataDir returns C:\ProgramData\Tripsilk on Windows (located through
// Windows, not the environment), ~/.tripsilk elsewhere.
func DataDir() string {
	if pd := win.ProgramData(); pd != "" {
		return filepath.Join(pd, "Tripsilk")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".tripsilk")
}

// legacyDirNames maps Tripsilk's settings folder names to the ones aWall,
// its earlier name, used beside them.
var legacyDirNames = map[string]string{"Tripsilk": "aWall", ".tripsilk": ".awall"}

// MigrateLegacy copies settings from aWall's folder (a sibling of dir) into
// dir the first time Tripsilk runs, so bait files, approvals and rules carry
// over. It never overwrites Tripsilk's own settings and leaves the old folder
// in place. It reports whether anything was copied.
func MigrateLegacy(dir string) (bool, error) {
	old, ok := legacyDirNames[filepath.Base(dir)]
	if !ok {
		return false, nil
	}
	oldDir := filepath.Join(filepath.Dir(dir), old)
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err == nil {
		return false, nil // already has its own settings
	}
	if _, err := os.Stat(filepath.Join(oldDir, "config.json")); err != nil {
		return false, nil // nothing to bring over
	}
	// Any user can create a folder under C:\ProgramData, so a folder with
	// the old name proves nothing: its settings could approve malware or
	// turn protection off. Only bring over what an admin wrote.
	if !win.AdminOwned(oldDir) {
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	copied := false
	for _, name := range []string{"config.json", "seen.json"} {
		fi, err := os.Lstat(filepath.Join(oldDir, name))
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > 16<<20 || !win.AdminOwned(filepath.Join(oldDir, name)) {
			continue // missing, a link, not a settings file, or planted
		}
		data, err := os.ReadFile(filepath.Join(oldDir, name))
		if err != nil {
			return copied, err
		}
		if err := WriteFileAtomic(filepath.Join(dir, name), data); err != nil {
			return copied, err
		}
		copied = true
	}
	return copied, nil
}

// AllowChild approves a program an agent may launch without alerts.
func (s *Store) AllowChild(agentImage, child string) error {
	agentImage, child = strings.ToLower(agentImage), strings.ToLower(child)
	if agentImage == "" || child == "" {
		return errors.New("missing agent or program")
	}
	return s.Update(func(c *Config) {
		if c.AgentChildAllow == nil {
			c.AgentChildAllow = map[string][]string{}
		}
		for _, x := range c.AgentChildAllow[agentImage] {
			if x == child {
				return
			}
		}
		c.AgentChildAllow[agentImage] = append(c.AgentChildAllow[agentImage], child)
	})
}

// RemoveChildAllow withdraws an approval.
func (s *Store) RemoveChildAllow(agentImage, child string) error {
	agentImage, child = strings.ToLower(agentImage), strings.ToLower(child)
	return s.Update(func(c *Config) {
		list := c.AgentChildAllow[agentImage]
		out := list[:0]
		for _, x := range list {
			if x != child {
				out = append(out, x)
			}
		}
		if len(out) == 0 {
			delete(c.AgentChildAllow, agentImage)
		} else {
			c.AgentChildAllow[agentImage] = out
		}
	})
}

// IsChildAllowed reports whether an agent may launch a program quietly.
func (s *Store) IsChildAllowed(agentImage, child string) bool {
	agentImage, child = strings.ToLower(agentImage), strings.ToLower(child)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.cfg.AgentChildAllow[agentImage] {
		if x == child {
			return true
		}
	}
	return false
}

// SetServiceRule limits an app to exactly these AI services.
func (s *Store) SetServiceRule(image string, services []string) error {
	image = strings.ToLower(image)
	if image == "" || len(services) == 0 {
		return errors.New("a rule needs a program and at least one service")
	}
	seen := map[string]bool{}
	var list []string
	for _, sv := range services {
		if sv != "" && !seen[sv] {
			seen[sv] = true
			list = append(list, sv)
		}
	}
	sort.Strings(list)
	return s.Update(func(c *Config) {
		if c.ServiceRules == nil {
			c.ServiceRules = map[string][]string{}
		}
		c.ServiceRules[image] = list
	})
}

// ClearServiceRule removes an app's rule.
func (s *Store) ClearServiceRule(image string) error {
	image = strings.ToLower(image)
	return s.Update(func(c *Config) { delete(c.ServiceRules, image) })
}

// ServiceRule returns an app's allowed services and whether it has a rule.
func (s *Store) ServiceRule(image string) ([]string, bool) {
	image = strings.ToLower(image)
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cfg.ServiceRules[image]
	return append([]string{}, r...), ok
}

// RuleAllows reports whether an app may use a service. Apps without a rule
// may use any service.
func (s *Store) RuleAllows(image, service string) bool {
	r, ok := s.ServiceRule(image)
	if !ok {
		return true
	}
	for _, x := range r {
		if x == service {
			return true
		}
	}
	return false
}

// AllowKeyReader approves a program to read one credential store quietly.
func (s *Store) AllowKeyReader(kind, image string) error {
	image = strings.ToLower(image)
	if kind == "" || image == "" {
		return errors.New("missing store or program")
	}
	return s.Update(func(c *Config) {
		if c.KeyAllow == nil {
			c.KeyAllow = map[string][]string{}
		}
		for _, x := range c.KeyAllow[kind] {
			if x == image {
				return
			}
		}
		c.KeyAllow[kind] = append(c.KeyAllow[kind], image)
	})
}

// RemoveKeyAllow withdraws an approval.
func (s *Store) RemoveKeyAllow(kind, image string) error {
	image = strings.ToLower(image)
	return s.Update(func(c *Config) {
		var out []string
		for _, x := range c.KeyAllow[kind] {
			if x != image {
				out = append(out, x)
			}
		}
		if len(out) == 0 {
			delete(c.KeyAllow, kind)
		} else {
			c.KeyAllow[kind] = out
		}
	})
}

// IsKeyReaderAllowed reports whether a program may read a store quietly.
func (s *Store) IsKeyReaderAllowed(kind, image string) bool {
	image = strings.ToLower(image)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range []string{kind, "*"} {
		for _, x := range s.cfg.KeyAllow[k] {
			if x == image {
				return true
			}
		}
	}
	return false
}

// AllowChannel approves a program to reach one control channel quietly.
func (s *Store) AllowChannel(image, channel string) error {
	image = strings.ToLower(image)
	if image == "" || channel == "" {
		return errors.New("missing program or channel")
	}
	return s.Update(func(c *Config) {
		if c.ChannelAllow == nil {
			c.ChannelAllow = map[string][]string{}
		}
		for _, x := range c.ChannelAllow[image] {
			if x == channel {
				return
			}
		}
		c.ChannelAllow[image] = append(c.ChannelAllow[image], channel)
	})
}

// RemoveChannelAllow withdraws a channel approval.
func (s *Store) RemoveChannelAllow(image, channel string) error {
	image = strings.ToLower(image)
	return s.Update(func(c *Config) {
		var out []string
		for _, x := range c.ChannelAllow[image] {
			if x != channel {
				out = append(out, x)
			}
		}
		if len(out) == 0 {
			delete(c.ChannelAllow, image)
		} else {
			c.ChannelAllow[image] = out
		}
	})
}

// IsChannelAllowed reports whether a program may reach a channel quietly.
func (s *Store) IsChannelAllowed(image, channel string) bool {
	image = strings.ToLower(image)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.cfg.ChannelAllow[image] {
		if x == channel {
			return true
		}
	}
	return false
}

func hasFold(list []string, x string) bool {
	for _, y := range list {
		if strings.EqualFold(y, x) {
			return true
		}
	}
	return false
}

// NoteDest records a place an agent's programs reached. It reports whether
// the place was new, and writes the settings only then.
func (s *Store) NoteDest(agent, dest string) (bool, error) {
	agent = strings.ToLower(agent)
	if agent == "" || dest == "" {
		return false, nil
	}
	s.mu.Lock()
	known := hasFold(s.cfg.DestUsed[agent], dest) || len(s.cfg.DestUsed[agent]) >= maxDests
	s.mu.Unlock()
	if known {
		return false, nil
	}
	return true, s.Update(func(c *Config) {
		if c.DestUsed == nil {
			c.DestUsed = map[string][]string{}
		}
		if !hasFold(c.DestUsed[agent], dest) && len(c.DestUsed[agent]) < maxDests {
			c.DestUsed[agent] = append(c.DestUsed[agent], dest)
		}
	})
}

// LockDests locks an agent's internet to the places it has used so far.
func (s *Store) LockDests(agent string) error {
	agent = strings.ToLower(agent)
	return s.updateErr(func(c *Config) error {
		used := c.DestUsed[agent]
		if len(used) == 0 {
			return errors.New("Tripsilk hasn't seen this app reach anywhere yet; use it for a while first")
		}
		if c.DestAllow == nil {
			c.DestAllow = map[string][]string{}
		}
		list := append([]string{}, used...)
		sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i]) < strings.ToLower(list[j]) })
		c.DestAllow[agent] = list
		return nil
	})
}

// UnlockDests lets an agent reach anywhere again.
func (s *Store) UnlockDests(agent string) error {
	agent = strings.ToLower(agent)
	return s.Update(func(c *Config) { delete(c.DestAllow, agent) })
}

// AllowDest adds a place to a locked agent's list.
func (s *Store) AllowDest(agent, dest string) error {
	agent = strings.ToLower(agent)
	if agent == "" || dest == "" {
		return errors.New("missing app or place")
	}
	return s.updateErr(func(c *Config) error {
		list, ok := c.DestAllow[agent]
		if !ok {
			return errors.New("this app's internet isn't locked")
		}
		if !hasFold(list, dest) {
			c.DestAllow[agent] = append(list, dest)
		}
		return nil
	})
}

// RemoveDest takes a place off a locked agent's list.
func (s *Store) RemoveDest(agent, dest string) error {
	agent = strings.ToLower(agent)
	return s.Update(func(c *Config) {
		list, ok := c.DestAllow[agent]
		if !ok {
			return
		}
		out := []string{}
		for _, x := range list {
			if !strings.EqualFold(x, dest) {
				out = append(out, x)
			}
		}
		c.DestAllow[agent] = out // stays locked, even when empty
	})
}

// DestAllowed reports whether agent's internet is locked and, if so,
// whether dest is on its list.
func (s *Store) DestAllowed(agent, dest string) (locked, allowed bool) {
	agent = strings.ToLower(agent)
	s.mu.Lock()
	defer s.mu.Unlock()
	list, locked := s.cfg.DestAllow[agent]
	return locked, locked && hasFold(list, dest)
}
