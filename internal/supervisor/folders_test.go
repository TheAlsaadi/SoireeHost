package supervisor

// S-22 and the owner decision of 13 Nov 2026 (review findings R-03, R-25):
// the supervisor checks every folder of the data folder table at start.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// installFolders creates the whole data folder table under a fresh root with
// the installed descriptors, owned by the test account (which plays every
// service account). tweak may change a row's descriptor, or return true to
// leave the folder for the caller to create. Every folder exists before any
// descriptor is applied: once a parent carries its OWNER RIGHTS entry, the
// test account could no longer set the descriptor of a folder it creates
// inside. The folders cannot all be removed afterwards without
// administrator rights, which is why they live under dataRoot.
func installFolders(t *testing.T, sid string, tweak func(i int, f *Folder) bool) Paths {
	t.Helper()
	p := Paths{Root: filepath.Join(dataRoot, "acl-"+randHex())}
	id := Identity{Supervisor: sid, Web: sid, Tunnel: sid}
	folders := p.Folders(id, []string{sid})
	skip := map[string]bool{}
	for i := range folders {
		if tweak != nil && tweak(i, &folders[i]) {
			skip[folders[i].Path] = true
			continue
		}
		if err := os.MkdirAll(folders[i].Path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// children first, so no parent's entries are in force yet
	for _, f := range slices.Backward(folders) {
		if skip[f.Path] {
			continue
		}
		if err := winsec.ForceSDDL(f.Path, "O:"+sid+f.SDDL); err != nil {
			t.Fatalf("%s: %v", f.Path, err)
		}
	}
	return p
}

func TestFolderCheckAcceptsInstalledTable(t *testing.T) {
	me, _ := winsec.CurrentCaller()
	p := installFolders(t, me.SID, nil)
	id := Identity{Supervisor: me.SID, Web: me.SID, Tunnel: me.SID}
	if err := checkFolders(p, id); err != nil {
		t.Fatalf("installed folders refused: %v", err)
	}
}

// Every folder of the table is checked: one that ordinary users may change
// stops the supervisor.
func TestFolderCheckRefusesWritableFolder(t *testing.T) {
	me, _ := winsec.CurrentCaller()
	id := Identity{Supervisor: me.SID, Web: me.SID, Tunnel: me.SID}
	for want, row := range (Paths{Root: `X:\root`}).Folders(id, nil) {
		rel, _ := filepath.Rel(`X:\root`, row.Path)
		t.Run(rel, func(t *testing.T) {
			p := installFolders(t, me.SID, func(i int, f *Folder) bool {
				if i == want {
					f.SDDL += "(A;OICI;0x1301bf;;;" + winsec.SIDUsers + ")"
				}
				return false
			})
			err := checkFolders(p, id)
			if err == nil || !strings.Contains(err.Error(), "refusing to run") || !strings.Contains(err.Error(), winsec.SIDUsers) {
				t.Fatalf("%s writable by Users: %v", rel, err)
			}
		})
	}
}

// A folder of the table that is a junction stops the supervisor, wherever
// the junction points.
func TestFolderCheckRefusesJunction(t *testing.T) {
	me, _ := winsec.CurrentCaller()
	id := Identity{Supervisor: me.SID, Web: me.SID, Tunnel: me.SID}
	target := t.TempDir()
	// tweak runs while the folders are created, before the root is locked
	p := installFolders(t, me.SID, func(_ int, f *Folder) bool {
		if strings.HasSuffix(f.Path, `\updates`) {
			testutil.Junction(t, f.Path, target)
			return true
		}
		return false
	})
	if err := checkFolders(p, id); err == nil || !strings.Contains(err.Error(), "not a plain folder") {
		t.Fatalf("junction accepted: %v", err)
	}
}

// A missing folder stops the supervisor with a pointer to setup.
func TestFolderCheckRefusesMissingFolder(t *testing.T) {
	me, _ := winsec.CurrentCaller()
	id := Identity{Supervisor: me.SID, Web: me.SID, Tunnel: me.SID}
	p := installFolders(t, me.SID, func(_ int, f *Folder) bool { return strings.HasSuffix(f.Path, `\pipe-web`) })
	if err := checkFolders(p, id); err == nil || !strings.Contains(err.Error(), "run setup again") {
		t.Fatalf("missing folder accepted: %v", err)
	}
}

// New runs the check when asked to.
func TestNewRefusesWritableFolders(t *testing.T) {
	me, _ := winsec.CurrentCaller()
	id := Identity{Supervisor: me.SID, Web: me.SID, Tunnel: me.SID}
	p := installFolders(t, me.SID, func(_ int, f *Folder) bool {
		if strings.HasSuffix(f.Path, `\secrets`) {
			f.SDDL += "(A;OICI;0x1301bf;;;" + winsec.SIDUsers + ")"
		}
		return false
	})
	if _, err := New(Options{Paths: p, Identity: id, CheckACLs: true}); err == nil || !strings.Contains(err.Error(), "refusing to run") {
		t.Fatalf("writable secrets folder: %v", err)
	}
}

// TestCheckProgramRefusesUserFolder: a program folder or program that an
// ordinary account owns or can change is refused (S-22). A test cannot make
// a folder owned by Administrators without elevation; the CI isolation job
// starts the installed services, which pass this check on the real folder.
func TestCheckProgramRefusesUserFolder(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "soireehost.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkProgram(exe); err == nil {
		t.Fatal("a program in a folder the test account owns was accepted")
	}
	if err := checkProgram(filepath.Join(dir, "missing.exe")); err == nil {
		t.Fatal("a missing program was accepted")
	}
}
