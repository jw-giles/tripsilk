package channels

import "testing"

func TestMatch(t *testing.T) {
	for d, want := range map[string]string{
		"api.telegram.org": "telegram-bot", "API.Telegram.org.": "telegram-bot",
		"discord.com": "discord", "canary.discord.com": "discord", "notdiscord.com": "",
		"abc123.ngrok-free.app": "tunnel", "random-words.trycloudflare.com": "tunnel",
		"pastebin.com": "paste", "x.oast.fun": "callback", "api.ipify.org": "ipcheck",
		"telegram.org": "", "web.telegram.org": "", "example.com": "", "": "",
	} {
		c, ok := Match(d)
		if (want == "") == ok || (ok && c.ID != want) {
			t.Errorf("Match(%q) = %q %v, want %q", d, c.ID, ok, want)
		}
	}
}

func TestNormal(t *testing.T) {
	tg, _ := Match("api.telegram.org")
	dc, _ := Match("discord.com")
	tun, _ := Match("x.trycloudflare.com")
	cases := []struct {
		c     Channel
		image string
		want  bool
	}{
		{tg, `C:\Users\j\AppData\Roaming\Telegram Desktop\Telegram.exe`, true},
		{tg, `C:\Python312\python.exe`, false},
		{tg, `C:\Program Files\Google\Chrome\Application\chrome.exe`, true},
		{dc, `C:\Users\j\AppData\Local\Discord\app-1.0.9\Discord.exe`, true},
		{dc, `C:\Users\j\AppData\Local\Discord\Update.exe`, true},
		{dc, `C:\Users\j\AppData\Local\Temp\x\Update.exe`, false},
		{dc, `C:\tools\node.exe`, false},
		{tun, `C:\Program Files\cloudflared\cloudflared.exe`, true},
		{tun, `C:\Users\j\AppData\Local\Temp\svc.exe`, false},
		{tg, ``, false},
	}
	signed := func(string) bool { return true }
	for _, c := range cases {
		if got := Normal(c.c, c.image, signed); got != c.want {
			t.Errorf("Normal(%s, %s) = %v, want %v", c.c.ID, c.image, got, c.want)
		}
	}
}

func TestUnsignedLookalikeIsNotExempt(t *testing.T) {
	tg, _ := Match("api.telegram.org")
	img := `C:\Users\j\AppData\Local\Temp\chrome.exe`
	if Normal(tg, img, func(string) bool { return false }) {
		t.Error("unsigned chrome.exe exempt")
	}
	if Normal(tg, img, nil) {
		t.Error("nil verifier exempt")
	}
}

func TestDiscordCDNIsItsOwnLowChannel(t *testing.T) {
	c, ok := Match("cdn.discordapp.com")
	if !ok || c.ID != "discord-cdn" || Severity(c.Kind) != "low" {
		t.Errorf("cdn: %+v %v", c, ok)
	}
	if c, _ := Match("discordapp.com"); c.ID != "discord" {
		t.Errorf("api: %s", c.ID)
	}
	if c, _ := Match("abc.devtunnels.ms"); c.ID != "devtunnels" || !Normal(c, `C:\x\Code.exe`, func(string) bool { return true }) {
		t.Errorf("devtunnels: %s", c.ID)
	}
	if _, ok := Match("canarytokens.com"); ok {
		t.Error("canarytokens is a defender's tool")
	}
}

func TestHosts(t *testing.T) {
	if !Host(`C:\Python312\python.exe`) || !Host(`C:\Windows\System32\svchost.exe`) || Host(`C:\x\mybot.exe`) {
		t.Error("Host")
	}
}

func TestEveryKindWorded(t *testing.T) {
	for _, c := range All() {
		if Why(c.Kind) == "" || Severity(c.Kind) == "" || c.Name == "" || len(c.Domains) == 0 {
			t.Errorf("%s incomplete", c.ID)
		}
	}
}
