package win

import "testing"

// The IDs as Microsoft publishes them (learn.microsoft.com, KNOWNFOLDERID).
func TestKnownFolderIDs(t *testing.T) {
	want := map[string]guid{
		"{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": FolderProgramData,
		"{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": FolderRoamingAppData,
		"{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": FolderLocalAppData,
		"{5E6C858F-0E22-4760-9AFE-EA3317B67173}": FolderProfile,
		"{905E63B6-C1BF-494E-B29C-65B732D3D21A}": FolderProgramFiles,
		"{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": FolderDocuments,
	}
	for s, g := range want {
		if g.String() != s {
			t.Errorf("got %s, want %s", g, s)
		}
	}
}
