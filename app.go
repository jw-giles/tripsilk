package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"tripsilk/internal/defender"
	"tripsilk/internal/engine"
	"tripsilk/internal/notify"
	"tripsilk/internal/service"
	"tripsilk/internal/win"
)

// App is the thin binding layer between the UI and the service. Every
// exported method is callable from JavaScript as window.go.main.App.<Name>.
type App struct {
	ctx      context.Context
	quitting bool
	hidNote  bool
	cancel   context.CancelFunc
	svc      *service.Service
	err      error
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	svc, err := service.New(engine.DataDir())
	if err != nil {
		a.err = fmt.Errorf("could not open settings in %s: %w", engine.DataDir(), err)
		return
	}
	a.svc = svc
	svc.Bus.Subscribe(func(al engine.Alert) {
		runtime.EventsEmit(ctx, "alert", al)
		if al.Severity == engine.SevCritical {
			runtime.WindowUnminimise(ctx)
			runtime.WindowShow(ctx)
		}
	})
	runCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	svc.Start(runCtx)
}

func (a *App) shutdown(ctx context.Context) {
	if a.cancel != nil {
		a.cancel()
	}
}

// beforeClose hides the window instead of quitting, so protection keeps
// running. Only the Quit button exits.
func (a *App) beforeClose(ctx context.Context) (prevent bool) {
	if a.quitting {
		return false
	}
	runtime.WindowHide(ctx)
	if !a.hidNote {
		a.hidNote = true
		go notify.Toast("Tripsilk is still protecting this PC",
			"Open Tripsilk again from its shortcut to see the dashboard. Use Quit in the dashboard to stop it.")
	}
	return true
}

func (a *App) secondInstance(options.SecondInstanceData) {
	if a.ctx != nil {
		runtime.WindowUnminimise(a.ctx)
		runtime.WindowShow(a.ctx)
	}
}

// Quit stops Tripsilk completely.
func (a *App) Quit() {
	a.quitting = true
	runtime.Quit(a.ctx)
}

func (a *App) SetToasts(on bool) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.SetToasts(on)
}

func (a *App) SetStartAtSignIn(on bool) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.SetStartAtSignIn(on)
}

func (a *App) ready() error {
	if a.err != nil {
		return a.err
	}
	if a.svc == nil {
		return fmt.Errorf("Tripsilk is still starting")
	}
	return nil
}

func (a *App) Snapshot() (service.Snapshot, error) {
	if err := a.ready(); err != nil {
		return service.Snapshot{}, err
	}
	return a.svc.Snapshot(), nil
}

func (a *App) Alerts() ([]engine.Alert, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	return a.svc.Bus.History(), nil
}

// AddBait opens a file picker and registers the chosen file as a tripwire.
// Returns "" if the user cancelled.
func (a *App) AddBait() (string, error) {
	if err := a.ready(); err != nil {
		return "", err
	}
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Choose a bait file — one nothing on this PC should ever open",
	})
	if err != nil || path == "" {
		return "", err
	}
	return path, a.svc.AddBait(path)
}

func (a *App) RemoveBait(path string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.RemoveBait(path)
}

func (a *App) Allow(image string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.Allow(image)
}

func (a *App) Disallow(image string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.Disallow(image)
}

func (a *App) Suspend(pid uint32, image string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.Suspend(pid, image)
}

func (a *App) Resume(pid uint32) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.Resume(pid)
}

func (a *App) Block(image string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.Block(image)
}

func (a *App) Unblock(rule string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.Unblock(rule)
}

func (a *App) QuickScan() error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.Scan(defender.QuickScan)
}

func (a *App) FullScan() error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.Scan(defender.FullScan)
}

func (a *App) UpdateDefinitions() error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.UpdateSignatures()
}

func (a *App) SetReadDetection(on bool) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.SetReadAuditing(on)
}

func (a *App) SetDryRun(on bool) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.SetDryRun(on)
}

func (a *App) Acknowledge() error {
	if err := a.ready(); err != nil {
		return err
	}
	a.svc.Acknowledge()
	return nil
}

func (a *App) AllowChild(agentImage, child string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.AllowChild(agentImage, child)
}

func (a *App) RemoveChildAllow(agentImage, child string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.RemoveChildAllow(agentImage, child)
}

func (a *App) AllowChannel(image, channel string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.AllowChannel(image, channel)
}

// FileHash returns a program file's SHA-256, for looking it up.
func (a *App) FileHash(image string) (string, error) {
	if err := a.ready(); err != nil {
		return "", err
	}
	return a.svc.FileHash(image)
}

// OpenURL opens a page in the user's browser. Only VirusTotal file pages
// are allowed: alert text comes from programs on the PC, and the dashboard
// must not become a way to open arbitrary links.
func (a *App) OpenURL(url string) error {
	const vt = "https://www.virustotal.com/gui/file/"
	sum := strings.TrimPrefix(url, vt)
	if !strings.HasPrefix(url, vt) || len(sum) != 64 || strings.Trim(sum, "0123456789abcdef") != "" {
		return fmt.Errorf("only VirusTotal file pages can be opened")
	}
	// Not runtime.BrowserOpenURL: Tripsilk runs as admin, and a browser
	// started from it would be too.
	return win.OpenAsUser(url)
}

func (a *App) CreateTripline() (string, error) {
	if err := a.ready(); err != nil {
		return "", err
	}
	return a.svc.CreateTripline()
}

func (a *App) FinishSetup() error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.FinishSetup()
}

func (a *App) ResumeAll(pid uint32) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.ResumeAll(pid)
}

func (a *App) SetAutoContain(on bool) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.SetAutoContain(on)
}

func (a *App) RemoveChannelAllow(image, channel string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.RemoveChannelAllow(image, channel)
}

// SetEventLog turns copying alerts to the Windows Event Log on or off.
func (a *App) SetEventLog(on bool) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.SetEventLog(on)
}

// RefreshRecap re-sums the weekly summary now.
func (a *App) RefreshRecap() error {
	if err := a.ready(); err != nil {
		return err
	}
	a.svc.RefreshRecap()
	return nil
}

// Internet lock for an AI app (see internal/service/allowlist.go).
func (a *App) LockDests(image string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.LockDests(image)
}

func (a *App) UnlockDests(image string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.UnlockDests(image)
}

func (a *App) AllowDest(image, dest string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.AllowDest(image, dest)
}

func (a *App) RemoveDest(image, dest string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.RemoveDest(image, dest)
}

func (a *App) LockToCurrent(image string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.LockToCurrent(image)
}

func (a *App) AllowService(image, service string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.AllowService(image, service)
}

func (a *App) ClearServiceRule(image string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.ClearServiceRule(image)
}

func (a *App) Terminate(pid uint32, image string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.Terminate(pid, image)
}

func (a *App) ScanProgram(image string) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.ScanProgram(image)
}

func (a *App) Disconnect() error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.Disconnect()
}

func (a *App) Reconnect() error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.Reconnect()
}

func (a *App) SetFolderProtection(on bool) error {
	if err := a.ready(); err != nil {
		return err
	}
	return a.svc.SetFolderProtection(on)
}

// CopyReport puts a summary of what Tripsilk sees on the clipboard, ready to
// paste into an AI assistant for help.
func (a *App) CopyReport() error {
	if err := a.ready(); err != nil {
		return err
	}
	return runtime.ClipboardSetText(a.ctx, a.svc.Report())
}
