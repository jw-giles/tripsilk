//go:build !windows

package defender

import "tripsilk/internal/engine"

func GetStatus() Status {
	return Status{Error: "Microsoft Defender is Windows-only"}
}

func RecentThreats() ([]Threat, error) { return nil, engine.ErrUnsupported }

func StartScan(kind ScanType) error { return engine.ErrUnsupported }

func UpdateSignatures() error { return engine.ErrUnsupported }

func GetFolderProtection() FolderProtection { return CFAUnknown }
func SetFolderProtection(on bool) error     { return engine.ErrUnsupported }
func ScanPath(path string) error            { return engine.ErrUnsupported }
