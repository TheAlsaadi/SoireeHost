package supervisor

import (
	"fmt"

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

// checkFolders refuses to run unless every folder in the table exists, is
// not a link or junction, and can be changed only by the accounts the table
// names (S-22; owner decision of 13 Nov 2026, review findings R-03 and
// R-25). Its owner must be SYSTEM, Administrators or the supervisor (SYSTEM
// or the supervisor for secrets): setup names Administrators or SYSTEM, and
// an owner of any other account means someone else created the folder.
func checkFolders(p Paths, id Identity, controlUsers []string) error {
	for _, f := range p.Folders(id, controlUsers) {
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
