//go:build windows

// Regression tests for DR-7 (docs/reviews/2026-11-12-skills-review.md).
// takeBack's walk runs without administrator rights here: the descriptor
// has no owner part, which changes nothing about which objects the walk
// reaches. A worker-owned empty folder that the walk has already listed is
// turned into a mount point while the walk is busy with an earlier sibling;
// the walk must not follow it outside the root.

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// fpMarker is an access entry nobody else would add: deny Anonymous
// (S-1-5-7) everything. Its presence shows the walk's descriptor landed.
const fpMarker = "(D;OICI;FA;;;S-1-5-7)"

func fpSDDL(t *testing.T) string {
	t.Helper()
	me, err := winsec.CurrentCaller()
	if err != nil {
		t.Fatal(err)
	}
	return "D:P" + fpMarker + "(A;OICI;FA;;;" + me.SID + ")"
}

// fpMakeMountPoint turns the empty folder dir into a mount point (junction)
// to target, in place, the way a process with write access to dir can
// without any privilege (FSCTL_SET_REPARSE_POINT, IO_REPARSE_TAG_MOUNT_POINT).
func fpMakeMountPoint(t *testing.T, dir, target string) {
	t.Helper()
	sub := `\??\` + target
	subU := windows.StringToUTF16(sub) // NUL terminated
	prnU := windows.StringToUTF16(target)
	subLen := (len(subU) - 1) * 2
	prnLen := (len(prnU) - 1) * 2
	pathBuf := make([]uint16, 0, len(subU)+len(prnU))
	pathBuf = append(pathBuf, subU...)
	pathBuf = append(pathBuf, prnU...)
	dataLen := 8 + len(pathBuf)*2
	buf := make([]byte, 8+dataLen)
	le16 := func(off, v int) { buf[off] = byte(v); buf[off+1] = byte(v >> 8) } //nolint:gosec // G115: low and high byte of a 16-bit field
	tag := uint32(windows.IO_REPARSE_TAG_MOUNT_POINT)
	buf[0], buf[1], buf[2], buf[3] = byte(tag), byte(tag>>8), byte(tag>>16), byte(tag>>24) //nolint:gosec // G115: the four bytes of a 32-bit tag
	le16(4, dataLen)
	le16(8, 0)         // SubstituteNameOffset
	le16(10, subLen)   // SubstituteNameLength
	le16(12, subLen+2) // PrintNameOffset
	le16(14, prnLen)   // PrintNameLength
	for i, c := range pathBuf {
		le16(16+2*i, int(c))
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatalf("opening %s: %v", dir, err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck // test
	var ret uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &ret, nil); err != nil { //nolint:gosec // G115: a buffer of a few hundred bytes
		t.Fatalf("setting mount point on %s: %v", dir, err)
	}
}

// fpHasMarker reports whether path's DACL carries fpMarker.
func fpHasMarker(t *testing.T, path string) bool {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return strings.Contains(sd.String(), ";;;AN)")
}

// fpLayout builds root\logs\web with padding files a000..a049 and an empty
// worker-made folder zz (sorted last), plus a victim tree outside root.
func fpLayout(t *testing.T) (root, web, zz, victim, victimFile string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "SoireeHost")
	web = filepath.Join(root, "logs", "web")
	zz = filepath.Join(web, "zz")
	if err := os.MkdirAll(zz, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		name := filepath.Join(web, "a0"+string(rune('0'+i/10))+string(rune('0'+i%10))+".log")
		if err := os.WriteFile(name, []byte("pad"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir() // stands in for C:\Users
	victim = filepath.Join(outside, "victim")
	if err := os.MkdirAll(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	victimFile = filepath.Join(victim, "profile.dat")
	if err := os.WriteFile(victimFile, []byte("user data"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(zz) }) // removes the link, not its target
	return root, web, zz, outside, victimFile
}

// fpTakeBackWalk is takeBack's walk (setup_windows.go): winsec.WalkTree with
// the same visit, applying sddl to every entry except multi-link files, plus
// a hook that runs before each visit, standing in for a concurrent worker.
// Without administrator rights it sets the access list only (no owner); the
// test owns every folder it walks.
func fpTakeBackWalk(root, sddl string, hook func(p string)) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	return winsec.WalkTree(root, func(e winsec.TreeEntry) error {
		if hook != nil {
			hook(filepath.Join(root, e.Rel))
		}
		if !e.IsDir() && e.Links > 1 {
			return nil
		}
		return windows.SetKernelObjectSecurity(e.Handle, windows.DACL_SECURITY_INFORMATION, sd)
	})
}

// DR-7: a junction swapped in after its parent was listed is taken over as a
// link object and never entered.
func TestTakeBackWalkIgnoresSwappedJunction(t *testing.T) {
	root, web, zz, outside, victimFile := fpLayout(t)
	sddl := fpSDDL(t)
	swapped := false
	var visited []string
	err := fpTakeBackWalk(root, sddl, func(p string) {
		visited = append(visited, p)
		// the worker acts after the walk listed logs\web (zz seen as a plain
		// folder) and while it is busy with an earlier sibling
		if !swapped && p == filepath.Join(web, "a025.log") {
			fpMakeMountPoint(t, zz, outside)
			swapped = true
		}
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, p := range visited {
		if strings.HasPrefix(p, zz+`\`) {
			t.Logf("walk reached %s (resolves outside the root)", p)
		}
	}
	if fpHasMarker(t, victimFile) || fpHasMarker(t, filepath.Join(outside, "victim")) {
		t.Fatalf("takeBack's walk re-permissioned %s, which is outside %s", victimFile, root)
	}
}

// Without a swap, nothing outside the root is touched.
func TestTakeBackWalkStaysInsideRoot(t *testing.T) {
	root, _, _, outside, victimFile := fpLayout(t)
	if err := fpTakeBackWalk(root, fpSDDL(t), nil); err != nil {
		t.Fatal(err)
	}
	if fpHasMarker(t, victimFile) || fpHasMarker(t, filepath.Join(outside, "victim")) {
		t.Fatal("touched outside the root without a swap")
	}
}

// A mount point that already exists when its parent is listed is not
// entered either; only the link object itself gets the descriptor.
func TestTakeBackWalkIgnoresExistingJunction(t *testing.T) {
	root, _, zz, outside, victimFile := fpLayout(t)
	fpMakeMountPoint(t, zz, outside)
	if err := fpTakeBackWalk(root, fpSDDL(t), nil); err != nil {
		t.Fatal(err)
	}
	if fpHasMarker(t, victimFile) || fpHasMarker(t, filepath.Join(outside, "victim")) {
		t.Fatal("a mount point present before the listing was followed")
	}
}
