package supervisor

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// Folder is one row of the data folder table (ADR-0006): where it is, who
// owns it, its protected access list, and the only accounts that may change
// it. Setup creates the folders from this table and the supervisor checks
// them against it at every start, so the two cannot drift apart.
type Folder struct {
	Path    string
	Owner   string
	SDDL    string // access list only; setup adds "O:" + Owner
	Writers []string
}

// Folders is the data folder table, data root first. controlUsers are the
// accounts allowed on the control pipe (control-users.json), which may read
// the control pipe's name.
func (p Paths) Folders(id Identity, controlUsers []string) []Folder {
	sup, web, tun := id.Supervisor, id.Web, id.Tunnel
	sy, ba := winsec.SIDSystem, winsec.SIDAdministrators
	admin := []string{sy, ba}
	withSup := []string{sy, ba, sup}
	return []Folder{
		{p.Root, ba, winsec.DataRootSDDL(sup, web, tun), admin},
		{p.Config(), ba, winsec.ConfigFolderSDDL(sup), withSup},
		// one folder per pipe-name file, readable by that pipe's clients (DR-1)
		{ipc.PipeFileFolder(p.Root, ipc.ControlPipeFile), ba, winsec.PipeNameFolderSDDL(sup, controlUsers...), withSup},
		{ipc.PipeFileFolder(p.Root, ipc.WebPipeFile), ba, winsec.PipeNameFolderSDDL(sup, web), withSup},
		{ipc.PipeFileFolder(p.Root, ipc.TunnelPipeFile), ba, winsec.PipeNameFolderSDDL(sup, tun), withSup},
		// secrets belong to the supervisor alone; SYSTEM owns the folder
		{p.Secrets(), sy, winsec.SecretsFolderSDDL(sup), []string{sy, sup}},
		{p.Logs(), ba, winsec.LogsFolderSDDL(sup), admin},
		{p.Audit(), ba, winsec.AuditFolderSDDL(sup), withSup},
		// worker log folders keep modify rights: log rotation deletes old
		// files (owner decision, 13 Nov 2026)
		{p.WebLogs(), ba, winsec.WorkerLogFolderSDDL(sup, web), []string{sy, ba, web}},
		{p.TunnelLogs(), ba, winsec.WorkerLogFolderSDDL(sup, tun), []string{sy, ba, tun}},
		{p.Updates(), ba, winsec.UpdatesFolderSDDL(sup), withSup},
	}
}

// programOwners and programWriters are who may own and change the program
// folder and soireehost.exe in it. The folder is in Program Files, whose
// permissions it inherits: SYSTEM, Administrators, TrustedInstaller, and the
// inherit-only CREATOR OWNER placeholder.
var (
	programOwners  = []string{winsec.SIDSystem, winsec.SIDAdministrators, winsec.SIDTrustedInstaller}
	programWriters = []string{winsec.SIDSystem, winsec.SIDAdministrators, winsec.SIDTrustedInstaller, winsec.SIDCreatorOwner}
)

// checkProgram refuses to run unless the program folder and the program are
// plain (no link or junction) and only administrators and the system can
// change them (S-22; Phase 7 compliance review, 21 Nov 2026). The three
// services run this file; an account that could replace it would run as all
// three at their next start.
func checkProgram(exe string) error {
	for _, p := range []string{filepath.Dir(exe), exe} {
		name, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(name)
		if err != nil {
			return fmt.Errorf("refusing to run: %s: %w (run Repair or install again)", p, err)
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (p != exe) != (attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
			return fmt.Errorf("refusing to run: %s is not a plain folder or file (a link or junction)", p)
		}
		if err := winsec.CheckOwnerAndWriters(p, programOwners, programWriters); err != nil {
			return fmt.Errorf("refusing to run: %w (run Repair or install again)", err)
		}
	}
	return nil
}

// checkFolders refuses to run unless every folder in the table exists, is
// not a link or junction, and can be changed only by the accounts the table
// names (S-22; owner decision of 13 Nov 2026, review findings R-03 and
// R-25). Its owner must be SYSTEM, Administrators or the supervisor (SYSTEM
// or the supervisor for secrets): setup names Administrators or SYSTEM, and
// an owner of any other account means someone else created the folder.
// Readers are not checked, so the control pipe's readers do not matter here.
func checkFolders(p Paths, id Identity) error {
	for _, f := range p.Folders(id, nil) {
		name, err := windows.UTF16PtrFromString(f.Path)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(name)
		if err != nil {
			return fmt.Errorf("refusing to run: %s: %w (run setup again)", f.Path, err)
		}
		if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("refusing to run: %s is not a plain folder (a file, link or junction)", f.Path)
		}
		owners := []string{winsec.SIDSystem, winsec.SIDAdministrators, id.Supervisor}
		if f.Owner == winsec.SIDSystem {
			owners = []string{winsec.SIDSystem, id.Supervisor}
		}
		if err := winsec.CheckOwnerAndWriters(f.Path, owners, f.Writers); err != nil {
			return fmt.Errorf("refusing to run: %w", err)
		}
	}
	return nil
}
