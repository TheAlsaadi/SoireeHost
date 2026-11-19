package setup

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// removedFolderSDDL protects the folder that holds program files still in
// use at uninstall: only SYSTEM and Administrators may open it, so nothing
// left there until the next restart can be run or replaced by anyone else.
const removedFolderSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// removeProgramFolder deletes dir and everything in it, including the
// program running this uninstall (ADR-0010). A file still in use (this
// process's own program, an open control panel) cannot be deleted but can
// be renamed, so it moves into a new folder beside dir, protected by
// removedSDDL, and both are marked for deletion at the next restart, the
// way Windows Installer removes files in use. No helper script, cmd.exe or
// delete-on-close trick is used: antivirus tools flag those. moved lists
// the files left for the restart; when it is empty, nothing remains.
func removeProgramFolder(dir, removedSDDL string) (moved []string, err error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var removed string // the folder for files in use, made when first needed
	var errs []error
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if os.RemoveAll(p) == nil {
			continue
		}
		if removed == "" {
			if removed, err = newRemovedFolder(filepath.Dir(dir), filepath.Base(dir), removedSDDL); err != nil {
				return moved, fmt.Errorf("making a folder for files in use: %w", err)
			}
		}
		dst := filepath.Join(removed, e.Name())
		if err := moveFile(p, dst); err != nil {
			errs = append(errs, fmt.Errorf("%s is in use and could not be moved: %w", p, err))
			continue
		}
		deleteAtRestart(dst)
		moved = append(moved, dst)
	}
	if removed != "" {
		// registered after its files, so the restart deletes them first
		deleteAtRestart(removed)
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return moved, errors.Join(errs...)
}

// newRemovedFolder creates <parent>\<base>.removed-<random> with sddl, in
// one call (convention rule 3). It is on the same volume as the program
// folder, so files can be renamed into it.
func newRemovedFolder(parent, base, sddl string) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	p := filepath.Join(parent, base+".removed-"+hex.EncodeToString(b[:]))
	if err := winsec.CreateFolderSDDL(p, sddl); err != nil {
		return "", err
	}
	return p, nil
}
