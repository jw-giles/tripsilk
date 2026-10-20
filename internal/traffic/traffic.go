// Package traffic turns raw connections into something a person can read:
// programs grouped under the program that launched them (motherships),
// sorted into types, talking to organizations rather than IP addresses.
// Everything here is pure data shaping, testable on any OS.
package traffic

import (
	"sort"
	"strings"
	"time"
)

// Categories, in the order the UI shows its filter chips.
const (
	CatAI      = "ai"
	CatBrowser = "browser"
	CatGame    = "game"
	CatChat    = "chat"
	CatCloud   = "cloud"
	CatDev     = "dev"
	CatSystem  = "system"
	CatOther   = "other"
)

var byName = map[string]string{
	// browsers
	"chrome.exe": CatBrowser, "msedge.exe": CatBrowser, "firefox.exe": CatBrowser,
	"brave.exe": CatBrowser, "opera.exe": CatBrowser, "vivaldi.exe": CatBrowser,
	"iexplore.exe": CatBrowser, "arc.exe": CatBrowser,
	// games and launchers
	"steam.exe": CatGame, "steamwebhelper.exe": CatGame, "epicgameslauncher.exe": CatGame,
	"riotclientservices.exe": CatGame, "battle.net.exe": CatGame, "galaxyclient.exe": CatGame,
	"eadesktop.exe": CatGame, "ubisoftconnect.exe": CatGame, "upc.exe": CatGame,
	"curseforge.exe": CatGame, "minecraftlauncher.exe": CatGame, "javaw.exe": CatOther,
	// chat and calls
	"discord.exe": CatChat, "slack.exe": CatChat, "teams.exe": CatChat, "ms-teams.exe": CatChat,
	"zoom.exe": CatChat, "telegram.exe": CatChat, "whatsapp.exe": CatChat, "signal.exe": CatChat,
	"skype.exe": CatChat,
	// cloud sync
	"onedrive.exe": CatCloud, "dropbox.exe": CatCloud, "googledrivefs.exe": CatCloud,
	"icloudservices.exe": CatCloud, "megasync.exe": CatCloud, "box.exe": CatCloud,
	// developer tools
	"code.exe": CatDev, "git.exe": CatDev, "git-remote-https.exe": CatDev, "node.exe": CatDev,
	"python.exe": CatDev, "pythonw.exe": CatDev, "go.exe": CatDev, "java.exe": CatDev,
	"idea64.exe": CatDev, "devenv.exe": CatDev, "ssh.exe": CatDev, "docker.exe": CatDev,
	"com.docker.backend.exe": CatDev, "studio64.exe": CatDev, "wails.exe": CatDev,
	// windows itself
	"system": CatSystem, "svchost.exe": CatSystem, "lsass.exe": CatSystem, "services.exe": CatSystem,
	"msmpeng.exe": CatSystem, "searchhost.exe": CatSystem, "explorer.exe": CatSystem,
	"backgroundtaskhost.exe": CatSystem, "wuauclt.exe": CatSystem, "sihost.exe": CatSystem,
	"smartscreen.exe": CatSystem, "wermgr.exe": CatSystem, "compattelrunner.exe": CatSystem,
	"spoolsv.exe": CatSystem, "searchapp.exe": CatSystem, "startmenuexperiencehost.exe": CatSystem,
	"widgets.exe": CatSystem, "phoneexperiencehost.exe": CatSystem, "mpdefendercoreservice.exe": CatSystem,
	"nissrv.exe": CatSystem, "securityhealthservice.exe": CatSystem, "officeclicktorun.exe": CatSystem,
	// AI apps (also detected by traffic to AI services)
	"claude.exe": CatAI, "chatgpt.exe": CatAI, "cursor.exe": CatAI, "ollama.exe": CatAI,
	"lm studio.exe": CatAI, "lmstudio.exe": CatAI, "windsurf.exe": CatAI,
}

// Path fragments that identify games installed by launchers.
var gamePaths = []string{`\steamapps\common\`, `\epic games\`, `\riot games\`, `\battle.net\`,
	`\gog galaxy\games\`, `\ea games\`, `\ubisoft game launcher\games\`, `\xboxgames\`}

func base(path string) string {
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		path = path[i+1:]
	}
	return strings.ToLower(path)
}

// Categorize sorts a program by name, then by where it is installed.
func Categorize(image string) string {
	if c, ok := byName[base(image)]; ok {
		return c
	}
	low := strings.ToLower(image)
	for _, g := range gamePaths {
		if strings.Contains(low, g) {
			return CatGame
		}
	}
	if strings.HasPrefix(low, `c:\windows\`) {
		return CatSystem
	}
	return CatOther
}

// ---- organizations ----

// Two-part public suffixes common enough to matter. Not the full public
// suffix list: an unknown one only makes the label slightly less tidy.
var twoPartSuffix = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "com.au": true, "net.au": true,
	"org.au": true, "co.jp": true, "ne.jp": true, "or.jp": true, "co.nz": true, "co.kr": true,
	"com.br": true, "com.cn": true, "com.mx": true, "co.in": true, "com.tr": true, "com.sg": true,
	"com.hk": true, "co.za": true, "com.tw": true, "com.ar": true,
}

// RegistrableDomain returns the part of a hostname an organization
// registers: api.steampowered.com -> steampowered.com.
func RegistrableDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	last2 := strings.Join(parts[len(parts)-2:], ".")
	if twoPartSuffix[last2] && len(parts) >= 3 {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return last2
}

// Known organizations by registrable domain.
var orgByDomain = map[string]string{
	"microsoft.com": "Microsoft", "windows.com": "Microsoft", "windowsupdate.com": "Microsoft",
	"live.com": "Microsoft", "office.com": "Microsoft", "office.net": "Microsoft", "msn.com": "Microsoft",
	"bing.com": "Microsoft", "azure.com": "Microsoft", "azureedge.net": "Microsoft", "msedge.net": "Microsoft",
	"microsoftonline.com": "Microsoft", "skype.com": "Microsoft", "xboxlive.com": "Microsoft",
	"msftconnecttest.com": "Microsoft", "trafficmanager.net": "Microsoft", "s-microsoft.com": "Microsoft",
	"sharepoint.com": "Microsoft", "onedrive.com": "Microsoft", "visualstudio.com": "Microsoft",
	"vscode-cdn.net": "Microsoft", "githubusercontent.com": "GitHub", "github.com": "GitHub",
	"google.com": "Google", "googleapis.com": "Google", "gstatic.com": "Google", "1e100.net": "Google",
	"googleusercontent.com": "Google", "youtube.com": "Google", "ytimg.com": "Google",
	"googlevideo.com": "Google", "doubleclick.net": "Google", "google-analytics.com": "Google",
	"steampowered.com": "Valve (Steam)", "steamcommunity.com": "Valve (Steam)", "steamserver.net": "Valve (Steam)",
	"steamcontent.com": "Valve (Steam)", "steamstatic.com": "Valve (Steam)", "valvesoftware.com": "Valve (Steam)",
	"discord.com": "Discord", "discord.gg": "Discord", "discordapp.com": "Discord", "discordapp.net": "Discord",
	"discord.media": "Discord",
	"amazonaws.com": "Amazon Web Services", "cloudfront.net": "Amazon CloudFront", "amazon.com": "Amazon",
	"akamai.net": "Akamai", "akamaiedge.net": "Akamai", "akamaized.net": "Akamai", "akadns.net": "Akamai",
	"edgekey.net": "Akamai", "edgesuite.net": "Akamai",
	"cloudflare.com": "Cloudflare", "cloudflare.net": "Cloudflare",
	"fastly.net": "Fastly", "apple.com": "Apple", "icloud.com": "Apple", "mzstatic.com": "Apple",
	"dropbox.com": "Dropbox", "dropboxapi.com": "Dropbox", "spotify.com": "Spotify", "scdn.co": "Spotify",
	"epicgames.com": "Epic Games", "riotgames.com": "Riot Games", "blizzard.com": "Blizzard",
	"battle.net": "Blizzard", "ea.com": "EA", "ubisoft.com": "Ubisoft", "twitch.tv": "Twitch",
	"zoom.us": "Zoom", "slack.com": "Slack", "slack-edge.com": "Slack",
	"anthropic.com": "Anthropic", "claude.ai": "Anthropic", "openai.com": "OpenAI", "chatgpt.com": "OpenAI",
	"openrouter.ai": "OpenRouter", "mistral.ai": "Mistral", "groq.com": "Groq", "x.ai": "xAI",
	"huggingface.co": "Hugging Face", "nvidia.com": "NVIDIA",
}

// Org names a hostname (or bare IP when no name is known) as the
// organization behind it, plus the domain shown in details.
func Org(host string) (org, domain string) {
	if host == "" {
		return "Unnamed address", ""
	}
	d := RegistrableDomain(host)
	if o, ok := orgByDomain[d]; ok {
		return o, d
	}
	return d, d
}

// ---- assembly ----

// Proc is the slice of process info traffic needs.
type Proc struct {
	PID     uint32
	PPID    uint32
	Image   string    // full path
	Created time.Time // zero when unknown
}

// Conn is one live connection.
type Conn struct {
	PID    uint32
	Remote string // ip:port
	IP     string
	Host   string // from the DNS cache, "" if unknown
	AI     string // AI provider label when the address serves an AI API
}

// Link is an app's traffic to one organization.
type Link struct {
	Org   string   `json:"org"`
	Hosts []string `json:"hosts"` // distinct hostnames, or addresses when unnamed
	Count int      `json:"count"`
	AI    bool     `json:"ai"`
	New   bool     `json:"new"`
}

// App is one program on the map. Satellites are programs it launched that
// also use the network (a game under Steam, a web view under Claude).
type App struct {
	Key        string   `json:"key"` // lowercase image path
	Image      string   `json:"image"`
	Label      string   `json:"label"`
	Category   string   `json:"category"`
	PIDs       []uint32 `json:"pids"`
	Mothership string   `json:"mothership,omitempty"` // key of the launching app
	Links      []Link   `json:"links"`
	Conns      int      `json:"conns"`
}

// Build groups connections into apps. procs supplies parents and images;
// novel reports whether an app-to-org link is new.
func Build(conns []Conn, procs []Proc, novel func(appKey, org string) bool) []App {
	byPID := make(map[uint32]Proc, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	apps := map[string]*App{}
	links := map[string]map[string]*Link{}
	hostSets := map[string]map[string]map[string]bool{}

	for _, c := range conns {
		p, ok := byPID[c.PID]
		if !ok || p.Image == "" {
			continue
		}
		key := strings.ToLower(p.Image)
		a := apps[key]
		if a == nil {
			a = &App{Key: key, Image: p.Image, Label: displayName(p.Image), Category: Categorize(p.Image)}
			apps[key] = a
			links[key] = map[string]*Link{}
			hostSets[key] = map[string]map[string]bool{}
		}
		if !containsPID(a.PIDs, c.PID) {
			a.PIDs = append(a.PIDs, c.PID)
		}
		a.Conns++
		org, _ := Org(c.Host)
		if c.AI != "" {
			org = c.AI
			a.Category = CatAI
		}
		l := links[key][org]
		if l == nil {
			l = &Link{Org: org, AI: c.AI != ""}
			links[key][org] = l
			hostSets[key][org] = map[string]bool{}
		}
		l.Count++
		name := c.Host
		if name == "" {
			name = c.IP
		}
		hostSets[key][org][name] = true
	}

	// Motherships: the nearest ancestor (different program) that is also on
	// the map, at most 8 levels up. Windows reuses PIDs, so a parent created
	// after its "child" is a recycled PID, not the real launcher: stop there.
	for key, a := range apps {
		for _, pid := range a.PIDs {
			cur := byPID[pid]
			for depth := 0; depth < 8; depth++ {
				parent, ok := byPID[cur.PPID]
				if !ok || cur.PPID == cur.PID || cur.PPID <= 4 {
					break
				}
				if !parent.Created.IsZero() && !cur.Created.IsZero() && parent.Created.After(cur.Created) {
					break
				}
				pk := strings.ToLower(parent.Image)
				if pk != key && apps[pk] != nil {
					a.Mothership = pk
					break
				}
				cur = parent
			}
			if a.Mothership != "" {
				break
			}
		}
	}
	// Never let two apps orbit each other: a cycle would hide both.
	for _, a := range apps {
		if m := apps[a.Mothership]; m != nil && m.Mothership == a.Key {
			a.Mothership = ""
		}
	}

	out := make([]App, 0, len(apps))
	for key, a := range apps {
		for org, l := range links[key] {
			for h := range hostSets[key][org] {
				l.Hosts = append(l.Hosts, h)
			}
			sort.Strings(l.Hosts)
			if len(l.Hosts) > 12 {
				l.Hosts = append(l.Hosts[:12], "…")
			}
			if novel != nil {
				l.New = novel(key, org)
			}
			a.Links = append(a.Links, *l)
		}
		sort.Slice(a.Links, func(i, j int) bool { return a.Links[i].Count > a.Links[j].Count })
		sort.Slice(a.PIDs, func(i, j int) bool { return a.PIDs[i] < a.PIDs[j] })
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Conns > out[j].Conns })
	return out
}

func containsPID(xs []uint32, p uint32) bool {
	for _, x := range xs {
		if x == p {
			return true
		}
	}
	return false
}

func displayName(image string) string {
	b := image
	if i := strings.LastIndexAny(b, `\/`); i >= 0 {
		b = b[i+1:]
	}
	return b
}
