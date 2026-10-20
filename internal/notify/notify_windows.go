//go:build windows

package notify

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"tripsilk/internal/win"
)

// powershellAUMID is the app identity Windows PowerShell registers for
// notifications. Toasts appear under "Windows PowerShell" until Tripsilk has
// an installer that registers its own identity.
const powershellAUMID = `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe`

// Toast shows a Windows notification. Title and body are passed as quoted
// PowerShell literals and XML-escaped inside the script.
func Toast(title, body string) error {
	script := `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; ` +
		`[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null; ` +
		`$t = [Security.SecurityElement]::Escape(` + win.PSQuote(Clip(title, 120)) + `); ` +
		`$b = [Security.SecurityElement]::Escape(` + win.PSQuote(Clip(body, 300)) + `); ` +
		`$x = New-Object Windows.Data.Xml.Dom.XmlDocument; ` +
		`$x.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>"); ` +
		`[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(` + win.PSQuote(powershellAUMID) + `).Show([Windows.UI.Notifications.ToastNotification]::new($x))`
	out, err := win.PowerShell(20*time.Second, script)
	if err != nil {
		return fmt.Errorf("toast: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// SetStartAtSignIn creates or removes a scheduled task that starts Tripsilk
// with administrator rights when the current user signs in. Windows won't
// auto-start an app that requires elevation from the Run key, so a task with
// highest privileges is the standard way.
//
// The task definition is written to workDir, Tripsilk's settings folder, under
// a random name Tripsilk creates itself, so programs without admin rights
// can't edit it. The task runs with admin rights: a definition a normal
// program could change between writing and schtasks reading it would let
// that program choose what runs as admin. The user's temp folder is not
// safe for this.
func SetStartAtSignIn(on bool, workDir string) error {
	if legacyTaskExists() {
		_, _ = schtasks(`/delete /f /tn "` + LegacyTaskName + `"`)
	}
	if !on {
		out, err := schtasks(`/delete /f /tn "` + TaskName + `"`)
		if err != nil && StartsAtSignIn() {
			return fmt.Errorf("schtasks delete: %s", strings.TrimSpace(string(out)))
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if strings.ContainsRune(exe, '"') {
		return fmt.Errorf("unexpected quote in program path")
	}
	// The task runs as the signed-in user, named by SID from Tripsilk's own
	// token rather than %USERNAME%, which the user's environment controls.
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	if workDir == "" {
		return fmt.Errorf("no settings folder for the task definition")
	}
	f, err := os.CreateTemp(workDir, "task-*.xml")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	_, werr := f.Write(UTF16LE(TaskXML(user, exe)))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if strings.ContainsRune(path, '"') {
		return fmt.Errorf("unexpected quote in temp path")
	}
	out, err := schtasks(`/create /f /tn "` + TaskName + `" /xml "` + path + `"`)
	if err != nil {
		return fmt.Errorf("schtasks create: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// StartsAtSignIn reports whether a sign-in task exists, Tripsilk's or the
// one aWall left behind.
func StartsAtSignIn() bool {
	_, err := schtasks(`/query /tn "` + TaskName + `"`)
	return err == nil || legacyTaskExists()
}

func legacyTaskExists() bool {
	_, err := schtasks(`/query /tn "` + LegacyTaskName + `"`)
	return err == nil
}

func schtasks(args string) ([]byte, error) {
	exe := win.SystemTool("schtasks.exe")
	return win.RunRaw(20*time.Second, exe, `schtasks.exe `+args)
}

// currentUserSID returns the SID of the user Tripsilk runs as.
func currentUserSID() (string, error) {
	t, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer t.Close()
	u, err := t.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String()
}
