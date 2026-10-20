// Package channels recognizes services malware and hijacked agents use as a
// control channel or an exit: chat-bot APIs and webhooks to take orders or
// report back, paste and file-drop sites to stage payloads or leak data,
// tunnels to expose the PC, and callback catchers attackers use to confirm a
// command ran.
//
// Each of these is ordinary for its own app and for a browser. The signal is
// a program with no reason to reach it doing so, such as a Python script
// talking to the Telegram bot API.
//
// Matching is by domain name, never by address: most of these sit behind
// shared CDN addresses (Discord webhooks are on Cloudflare), so an address
// says nothing about which service was reached.
package channels

import (
	"path/filepath"
	"strings"
)

// Kind groups channels for the alert wording.
type Kind string

const (
	Bot      Kind = "bot"      // chat-bot APIs and webhooks
	Paste    Kind = "paste"    // paste and file-drop sites
	Tunnel   Kind = "tunnel"   // reverse tunnels that expose the PC
	Callback Kind = "callback" // out-of-band callback catchers
	IPCheck  Kind = "ipcheck"  // "what's my IP" lookups
	FileHost Kind = "filehost" // general file hosts attackers often reuse
)

// Channel is one recognized service.
type Channel struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Kind    Kind     `json:"kind"`
	Domains []string `json:"-"` // the domain and everything under it
	// Owners are programs (lowercase base names) for which this is their
	// own service, so reaching it is normal.
	Owners []string `json:"-"`
}

var list = []Channel{
	// Before "discord": these are under discordapp.com/.net too.
	{ID: "discord-cdn", Name: "Discord's file host", Kind: FileHost,
		Domains: []string{"cdn.discordapp.com", "media.discordapp.net", "images-ext-1.discordapp.net", "images-ext-2.discordapp.net"},
		Owners:  []string{"discord.exe", "discordcanary.exe", "discordptb.exe", "vesktop.exe", "webcord.exe"}},
	{ID: "telegram-bot", Name: "the Telegram bot API", Kind: Bot,
		Domains: []string{"api.telegram.org"},
		Owners:  []string{"telegram.exe", "ayugram.exe", "kotatogram.exe", "64gram.exe", "unigram.exe"}},
	{ID: "discord", Name: "Discord (webhooks and bot API)", Kind: Bot,
		Domains: []string{"discord.com", "discordapp.com", "discord.gg"},
		Owners:  []string{"discord.exe", "discordcanary.exe", "discordptb.exe", "vesktop.exe", "webcord.exe"}},
	{ID: "slack-hooks", Name: "Slack webhooks", Kind: Bot,
		Domains: []string{"hooks.slack.com"},
		Owners:  []string{"slack.exe"}},
	{ID: "paste", Name: "a paste site", Kind: Paste,
		Domains: []string{"pastebin.com", "paste.ee", "hastebin.com", "hastebin.skyra.pw", "rentry.co", "rentry.org",
			"dpaste.org", "dpaste.com", "ghostbin.co", "termbin.com", "paste.c-net.org", "pastes.io",
			"justpaste.it", "controlc.com", "telegra.ph", "paste.rs", "ix.io", "sprunge.us"}},
	{ID: "filedrop", Name: "an anonymous file-drop site", Kind: Paste,
		Domains: []string{"transfer.sh", "file.io", "0x0.st", "temp.sh", "gofile.io", "anonfiles.com",
			"catbox.moe", "litterbox.catbox.moe", "bashupload.com", "oshi.at", "tmpfiles.org", "filebin.net"}},
	{ID: "tunnel", Name: "a tunnel service", Kind: Tunnel,
		Domains: []string{"ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok.dev", "ngrok-free.dev", "tunnel.ngrok.com",
			"trycloudflare.com", "loca.lt", "localtunnel.me", "serveo.net", "localhost.run", "lhr.life",
			"pinggy.io", "pinggy.link", "bore.pub", "playit.gg", "portmap.io", "portmap.host",
			"tunnelmole.net", "tunnelto.dev", "localxpose.io", "loclx.io", "telebit.cloud",
			"zrok.io", "packetriot.com", "pagekite.me"},
		Owners: []string{"ngrok.exe", "cloudflared.exe", "pinggy.exe", "playit.exe", "zrok.exe"}},
	{ID: "devtunnels", Name: "Microsoft Dev Tunnels", Kind: Tunnel,
		Domains: []string{"devtunnels.ms"},
		Owners:  []string{"code.exe", "code - insiders.exe", "code-tunnel.exe", "devenv.exe", "devtunnel.exe"}},
	{ID: "callback", Name: "an attack callback catcher", Kind: Callback,
		Domains: []string{"webhook.site", "requestbin.net", "requestbin.com", "pipedream.net", "requestcatcher.com",
			"interact.sh", "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me",
			"burpcollaborator.net", "oastify.com", "dnslog.cn", "ceye.io", "beeceptor.com"}},
	{ID: "ipcheck", Name: "a \"what's my IP\" lookup", Kind: IPCheck,
		Domains: []string{"api.ipify.org", "api64.ipify.org", "ipinfo.io", "ifconfig.me", "ifconfig.co", "icanhazip.com",
			"ipecho.net", "checkip.amazonaws.com", "ip-api.com", "wtfismyip.com", "myexternalip.com", "ident.me",
			"ipapi.co", "freegeoip.app", "ipwho.is"}},
}

// Browsers reach all of these legitimately on the user's behalf. A
// browser-based agent is indistinguishable from the user here; that gap is
// listed under "Not covered".
var browsers = map[string]bool{
	"chrome.exe": true, "msedge.exe": true, "firefox.exe": true, "brave.exe": true, "opera.exe": true,
	"opera_gx.exe": true, "vivaldi.exe": true, "arc.exe": true, "librewolf.exe": true, "waterfox.exe": true,
	"iexplore.exe": true, "msedgewebview2.exe": true, "zen.exe": true, "floorp.exe": true, "thorium.exe": true,
	"chromium.exe": true, "tor.exe": true, "firefox-esr.exe": true,
	// Embedded browsers that render web pages inside other apps.
	"steamwebhelper.exe": true, "epicwebhelper.exe": true, "cefsharp.browsersubprocess.exe": true,
	"qtwebengineprocess.exe": true,
}

// hosts run other people's code: a script, a DLL, a service. Approving one
// would approve everything run through it, so Tripsilk won't.
var hosts = map[string]bool{
	"python.exe": true, "pythonw.exe": true, "py.exe": true, "node.exe": true, "deno.exe": true, "bun.exe": true,
	"java.exe": true, "javaw.exe": true, "ruby.exe": true, "perl.exe": true, "php.exe": true,
	"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true, "wscript.exe": true, "cscript.exe": true,
	"mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true, "svchost.exe": true, "dllhost.exe": true,
	"conhost.exe": true, "wsl.exe": true, "bash.exe": true, "msbuild.exe": true, "curl.exe": true, "wget.exe": true,
	"installutil.exe": true, "regasm.exe": true, "msiexec.exe": true, "wmic.exe": true,
}

// Host reports whether image is a script engine or system host that can't
// be approved as a whole.
func Host(image string) bool { return hosts[baseName(image)] }

func baseName(image string) string {
	return strings.ToLower(filepath.Base(strings.ReplaceAll(image, `\`, "/")))
}

// Match returns the channel a domain belongs to. Matching respects label
// boundaries: "notdiscord.com" is not Discord.
func Match(domain string) (Channel, bool) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" {
		return Channel{}, false
	}
	for _, c := range list {
		for _, base := range c.Domains {
			if d == base || strings.HasSuffix(d, "."+base) {
				return c, true
			}
		}
	}
	return Channel{}, false
}

// Normal reports whether reaching c is ordinary for the program at image:
// the service's own app, or a browser, and only when signed reports the
// file carries a valid signature. A name alone proves nothing: malware can
// call itself chrome.exe.
func Normal(c Channel, image string, signed func(path string) bool) bool {
	name := baseName(image)
	owner := browsers[name]
	for _, o := range c.Owners {
		owner = owner || name == o
	}
	// Discord's updater is Update.exe in its own install folder.
	if (c.ID == "discord" || c.ID == "discord-cdn") && name == "update.exe" {
		owner = strings.Contains(strings.ToLower(image), `\appdata\local\discord\`)
	}
	return owner && signed != nil && signed(image)
}

// Severity is how loud an alert for this kind should be, as a string the
// service maps onto its own levels: "high", "medium" or "low".
func Severity(k Kind) string {
	switch k {
	case Bot, Tunnel, Callback:
		return "high"
	case Paste:
		return "medium"
	default:
		return "low"
	}
}

// Why is one plain sentence on why the kind matters.
func Why(k Kind) string {
	switch k {
	case Bot:
		return "Malware uses chat-bot services to take orders and send back stolen data, because the traffic looks like ordinary chat."
	case Paste:
		return "Attackers use paste and file-drop sites to fetch their next stage or to leak copied files."
	case Tunnel:
		return "A tunnel makes a program on this PC reachable from the internet, past your router and firewall."
	case Callback:
		return "These sites exist to tell an attacker that a command they planted actually ran."
	case FileHost:
		return "Attackers often keep their malware on Discord's file host, because it's trusted and rarely blocked."
	default:
		return "Malware often checks the PC's public address first, to report where it landed."
	}
}

// All lists the channels, for the coverage page.
func All() []Channel { return append([]Channel{}, list...) }
