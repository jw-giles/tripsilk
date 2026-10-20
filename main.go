package main

import (
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tripsilk/internal/engine"
	"tripsilk/internal/service"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// The uninstaller runs "Tripsilk.exe --uninstall-cleanup" before removing
	// files, so uninstalling never leaves firewall blocks, frozen processes
	// or the sign-in task behind.
	if len(os.Args) > 1 && os.Args[1] == "--uninstall-cleanup" {
		os.Exit(uninstallCleanup())
	}
	app := NewApp()
	err := wails.Run(&options.App{
		Title:            "Tripsilk",
		Width:            1180,
		Height:           800,
		MinWidth:         760,
		MinHeight:        560,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 245, G: 246, B: 243, A: 255},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		OnBeforeClose:    app.beforeClose,
		// A second launch (Start menu, shortcut) shows the running window
		// instead of starting another copy.
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "b71e9c20-tripsilk-desktop",
			OnSecondInstanceLaunch: app.secondInstance,
		},
		Bind: []interface{}{app},
	})
	if err != nil {
		log.Fatal(err)
	}
}

func uninstallCleanup() int {
	dir := engine.DataDir()
	errs := service.Cleanup(dir)
	var b strings.Builder
	fmt.Fprintf(&b, "Tripsilk uninstall cleanup %s\n", time.Now().Format(time.RFC1123))
	if len(errs) == 0 {
		b.WriteString("Everything undone.\n")
	}
	for _, e := range errs {
		fmt.Fprintf(&b, "Not undone: %v\n", e)
	}
	_ = engine.WriteFileAtomic(filepath.Join(dir, "uninstall.log"), []byte(b.String()))
	if len(errs) > 0 {
		return 1
	}
	return 0
}
