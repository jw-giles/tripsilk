package agentguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"tripsilk/internal/win"
)

// AgentConfig is a known AI tool configuration file that can list MCP
// servers (tools the agent may call).
//
// Locations come from each product's documentation as of mid-2026 and are
// not verified against every version; a missing file is reported as such,
// not as an error.
type AgentConfig struct {
	Product string
	Path    string
}

// KnownConfigs returns candidate config paths for this user.
func KnownConfigs() []AgentConfig {
	home := win.Home()
	appdata := win.AppData()
	var out []AgentConfig
	add := func(product, path string) { out = append(out, AgentConfig{product, path}) }
	if appdata != "" {
		add("Claude Desktop", filepath.Join(appdata, "Claude", "claude_desktop_config.json"))
		add("VS Code", filepath.Join(appdata, "Code", "User", "mcp.json"))
		add("VS Code", filepath.Join(appdata, "Code", "User", "settings.json"))
	}
	if home != "" {
		add("Claude Code", filepath.Join(home, ".claude.json"))
		add("Claude Code", filepath.Join(home, ".claude", "settings.json"))
		add("Cursor", filepath.Join(home, ".cursor", "mcp.json"))
		add("Windsurf", filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"))
	}
	return out
}

// MCPServers extracts server name -> launch description from a config file.
// It understands the common shapes:
//
//	{"mcpServers": {...}}                     Claude Desktop, Claude Code, Cursor, Windsurf
//	{"servers": {...}}                        VS Code mcp.json
//	{"mcp": {"servers": {...}}}               VS Code settings.json
//	{"projects": {"<dir>": {"mcpServers"}}}   Claude Code per-project servers
func MCPServers(data []byte) (map[string]string, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(StripJSONC(data), &root); err != nil {
		return nil, err
	}
	out := map[string]string{}
	collect := func(prefix string, raw json.RawMessage) {
		var servers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
			URL     string   `json:"url"`
			Type    string   `json:"type"`
		}
		if json.Unmarshal(raw, &servers) != nil {
			return
		}
		for name, s := range servers {
			desc := s.URL
			if s.Command != "" {
				desc = strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
			}
			if desc == "" {
				desc = s.Type
			}
			out[prefix+name] = desc
		}
	}
	if raw, ok := root["mcpServers"]; ok {
		collect("", raw)
	}
	if raw, ok := root["servers"]; ok {
		collect("", raw)
	}
	if raw, ok := root["mcp"]; ok {
		var mcp map[string]json.RawMessage
		if json.Unmarshal(raw, &mcp) == nil {
			if s, ok := mcp["servers"]; ok {
				collect("", s)
			}
		}
	}
	if raw, ok := root["projects"]; ok {
		var projects map[string]map[string]json.RawMessage
		if json.Unmarshal(raw, &projects) == nil {
			for dir, p := range projects {
				if s, ok := p["mcpServers"]; ok {
					collect(baseAny(dir)+": ", s)
				}
			}
		}
	}
	return out, nil
}

// ServerChange is one difference between two MCP server sets.
type ServerChange struct {
	Name, Before, After string
}

// DiffServers lists added and changed servers (removals are not a threat).
func DiffServers(old, cur map[string]string) []ServerChange {
	var out []ServerChange
	for name, after := range cur {
		if before, ok := old[name]; !ok || before != after {
			out = append(out, ServerChange{name, old[name], after})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ConfigWatch remembers MCP server sets per file and reports changes.
type ConfigWatch struct {
	known map[string]map[string]string // path -> servers; nil map = file absent
	init  bool
}

func NewConfigWatch() *ConfigWatch { return &ConfigWatch{known: map[string]map[string]string{}} }

// ConfigStatus is shown in the dashboard.
type ConfigStatus struct {
	Product string `json:"product"`
	Path    string `json:"path"`
	Found   bool   `json:"found"`
	Servers int    `json:"servers"`
	Error   string `json:"error,omitempty"`
}

// Check reads each config and returns changes since the last call. The first
// call records a baseline.
func (w *ConfigWatch) Check(configs []AgentConfig) ([]ConfigStatus, map[AgentConfig][]ServerChange) {
	var status []ConfigStatus
	changes := map[AgentConfig][]ServerChange{}
	for _, c := range configs {
		st := ConfigStatus{Product: c.Product, Path: c.Path}
		data, err := os.ReadFile(c.Path)
		if err != nil {
			if !os.IsNotExist(err) {
				st.Error = err.Error()
			}
			status = append(status, st)
			continue
		}
		st.Found = true
		servers, err := MCPServers(data)
		if err != nil {
			// Files mid-write or with comments (VS Code allows JSONC).
			st.Error = fmt.Sprintf("couldn't read MCP servers: %v", err)
			status = append(status, st)
			continue
		}
		st.Servers = len(servers)
		status = append(status, st)
		// After the baseline, a config that appears for the first time
		// reports all its servers as new.
		if w.init {
			if d := DiffServers(w.known[c.Path], servers); len(d) > 0 {
				changes[c] = d
			}
		}
		w.known[c.Path] = servers
	}
	w.init = true
	return status, changes
}

// StripJSONC removes // and /* */ comments and trailing commas outside of
// strings, turning VS Code-style JSONC into plain JSON.
func StripJSONC(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inStr, esc := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			if i < len(in) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++ // skip the closing '/'
		case c == ']' || c == '}':
			// drop a trailing comma before this closer
			j := len(out) - 1
			for j >= 0 && (out[j] == ' ' || out[j] == '\t' || out[j] == '\n' || out[j] == '\r') {
				j--
			}
			if j >= 0 && out[j] == ',' {
				out = append(out[:j], out[j+1:]...)
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// baseAny returns the last path element, splitting on both / and \.
func baseAny(p string) string {
	p = strings.TrimRight(p, `/\\`)
	if i := strings.LastIndexAny(p, `/\\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
