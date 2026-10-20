package agentguard

import (
	"regexp"
	"strings"
)

// Level is how concerning a spawn is.
type Level int

const (
	Ignore  Level = iota
	Notice        // worth knowing: a shell or network tool
	Warning       // a system tool rarely needed by an assistant
	Severe        // matches a known attack pattern
)

// Tool categories by image base name. Shells are normal for coding agents,
// so they start at Notice and escalate only on red-flag command lines.
var (
	shells = map[string]bool{
		"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true,
		"wsl.exe": true, "bash.exe": true,
	}
	fetchers = map[string]bool{
		"curl.exe": true, "wget.exe": true, "ftp.exe": true, "tftp.exe": true,
		"scp.exe": true, "sftp.exe": true, "ssh.exe": true,
	}
	// Signed Windows tools often abused to run or fetch code, change
	// startup, or cover tracks. An assistant rarely has a reason to call them.
	systemTools = map[string]string{
		"certutil.exe":    "can download and decode files",
		"bitsadmin.exe":   "can download files in the background",
		"mshta.exe":       "runs HTML applications",
		"rundll32.exe":    "runs code inside DLLs",
		"regsvr32.exe":    "can load code from a file or URL",
		"wscript.exe":     "runs scripts",
		"cscript.exe":     "runs scripts",
		"msiexec.exe":     "installs software",
		"installutil.exe": "can run code from .NET assemblies",
		"regasm.exe":      "can run code from .NET assemblies",
		"regsvcs.exe":     "can run code from .NET assemblies",
		"cmstp.exe":       "can run code from connection profiles",
		"wmic.exe":        "runs system management commands",
		"schtasks.exe":    "creates scheduled tasks",
		"reg.exe":         "edits the registry",
		"sc.exe":          "creates and changes services",
		"netsh.exe":       "changes network and firewall settings",
		"vssadmin.exe":    "manages backup snapshots",
		"wbadmin.exe":     "manages backups",
		"bcdedit.exe":     "changes boot settings",
		"wevtutil.exe":    "can clear event logs",
		"icacls.exe":      "changes file permissions",
		"takeown.exe":     "takes ownership of files",
		"cmdkey.exe":      "lists and manages saved credentials",
		"net.exe":         "manages users and network shares",
		"net1.exe":        "manages users and network shares",
	}
)

// redFlag is a lowercase command-line fragment and what it suggests.
type redFlag struct{ frag, why string }

// Command-line fragments that escalate any spawn to Severe. These are
// well-known indicators from public detection rule sets.
var redFlags = []redFlag{
	{"add-mppreference", "tries to add a Defender exclusion"},
	{"set-mppreference", "tries to change Defender settings"},
	{"frombase64string", "decodes hidden content"},
	{"downloadstring", "downloads and runs code"},
	{"downloadfile", "downloads a file"},
	{"invoke-expression", "runs text as code"},
	{"-windowstyle hidden", "hides its window"},
	{"-w hidden", "hides its window"},
	{"vssadmin delete", "deletes backup snapshots"},
	{"shadowcopy delete", "deletes backup snapshots"},
	{"wevtutil cl", "clears event logs"},
	{"clear-eventlog", "clears event logs"},
	{"bcdedit /set", "changes boot settings"},
	{"\\.ssh\\", "touches SSH keys"},
	{"/.ssh/", "touches SSH keys"},
	{"\\.aws\\", "touches cloud credentials"},
	{"login data", "touches saved browser passwords"},
	{"\\cookies", "touches browser cookies"},
	{"reg save hklm\\sam", "copies the password database"},
	{"reg save hklm\\security", "copies security secrets"},
	{"currentversion\\run", "adds something that runs at startup"},
	{"\\start menu\\programs\\startup", "adds something that runs at startup"},
	{"schtasks /create", "creates a scheduled task"},
	{"-urlcache", "downloads a file"},
}

var iexRe = regexp.MustCompile(`(^|[^a-z0-9_-])iex([^a-z0-9_-]|$)`)

// psEncoded reports whether a PowerShell command line uses -EncodedCommand
// in any of the abbreviations PowerShell accepts (-e, -ec, -en, -enc, ...).
// Only applied to powershell/pwsh: "-e" means something else to other tools.
func psEncoded(cmd string) bool {
	for _, tok := range strings.Fields(cmd) {
		if len(tok) < 2 || (tok[0] != '-' && tok[0] != '/') {
			continue
		}
		t := tok[1:]
		if t == "ec" || (t[0] == 'e' && strings.HasPrefix("encodedcommand", t)) {
			return true
		}
	}
	return false
}

// Verdict is the classifier output for one spawn.
type Verdict struct {
	Level  Level
	Reason string
}

// Classify judges a process launched by an agent.
func Classify(p Proc) Verdict {
	name := lower(p.Name)
	cmd := " " + lower(p.CmdLine) + " "
	if (name == "powershell.exe" || name == "pwsh.exe") && psEncoded(cmd) {
		return Verdict{Severe, "Its command line runs a hidden (encoded) command."}
	}
	if iexRe.MatchString(cmd) {
		return Verdict{Severe, "Its command line runs text as code."}
	}
	for _, f := range redFlags {
		if strings.Contains(cmd, f.frag) {
			return Verdict{Severe, "Its command line " + f.why + "."}
		}
	}
	if why, ok := systemTools[name]; ok {
		return Verdict{Warning, "This Windows tool " + why + ". AI assistants rarely need it."}
	}
	if fetchers[name] {
		return Verdict{Notice, "This tool transfers data over the network."}
	}
	if shells[name] {
		return Verdict{Notice, "A command shell was opened. Normal for coding assistants; check the command."}
	}
	return Verdict{Ignore, ""}
}
