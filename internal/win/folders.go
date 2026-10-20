package win

import (
	"os"
	"path/filepath"
	"runtime"
)

// Folder helpers. On Windows they ask Windows (see paths_windows.go) and
// never read environment variables; elsewhere, where Tripsilk only runs its
// tests, they fall back to the environment.

func known(id guid, env string) string {
	if runtime.GOOS == "windows" {
		return KnownFolder(id)
	}
	return os.Getenv(env)
}

// ProgramData is C:\ProgramData. On Windows it falls back to the standard
// location rather than to %ProgramData%.
func ProgramData() string {
	if p := known(FolderProgramData, "ProgramData"); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		return `C:\ProgramData`
	}
	return ""
}

// ProgramFiles is C:\Program Files (for a 64-bit Tripsilk), or "" when unknown.
func ProgramFiles() string { return known(FolderProgramFiles, "ProgramFiles") }

// AppData is the user's roaming AppData folder.
func AppData() string { return known(FolderRoamingAppData, "APPDATA") }

// LocalAppData is the user's local AppData folder.
func LocalAppData() string { return known(FolderLocalAppData, "LOCALAPPDATA") }

// Documents is the user's Documents folder (wherever it's redirected to).
func Documents() string {
	if runtime.GOOS == "windows" {
		return KnownFolder(FolderDocuments)
	}
	h, _ := os.UserHomeDir()
	if h == "" {
		return ""
	}
	return filepath.Join(h, "Documents")
}

// Home is the user's profile folder.
func Home() string {
	if runtime.GOOS == "windows" {
		return KnownFolder(FolderProfile)
	}
	h, _ := os.UserHomeDir()
	return h
}

// SystemTool returns the full path of a program in System32.
func SystemTool(name string) string {
	if d := SystemDir(); d != "" {
		return filepath.Join(d, name)
	}
	return filepath.Join(`C:\Windows\System32`, name)
}
