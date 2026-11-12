package winsec

import "fmt"

// Access masks used in the descriptors below.
const (
	// fileModify is the "Modify" right on files and folders: read, write,
	// execute and delete, but not change permissions or take ownership.
	fileModify = "0x1301bf"
	// fileReadAppend lets a principal read a file and add to its end, but not
	// change what is already there: FILE_GENERIC_READ | FILE_APPEND_DATA.
	fileReadAppend = "0x12008d"
	// dirReadAddFile lets a principal list a folder and create files in it:
	// FILE_GENERIC_READ | FILE_ADD_FILE.
	dirReadAddFile = "0x12008b"
	// dirTraverse lets a principal open a folder to reach a subfolder:
	// FILE_GENERIC_READ | FILE_TRAVERSE.
	dirTraverse = "0x1200a9"
	// pipeClient is what a pipe client gets: FILE_GENERIC_READ |
	// FILE_WRITE_DATA. Not GENERIC_WRITE, whose FILE_APPEND_DATA bit is
	// FILE_CREATE_PIPE_INSTANCE on a pipe and would let a client create a
	// rogue instance of the server's pipe.
	pipeClient = "0x12008b"
)

// PipeClientAccess is the access a client asks for when it opens a pipe; it
// matches pipeClient.
const PipeClientAccess = 0x12008b

// ControlPipeSDDL is the security descriptor of the control pipe
// (S-30): owned by the server; NETWORK denied; read and write for SYSTEM,
// Administrators and each of users; full access for the server so it can
// create more pipe instances.
func ControlPipeSDDL(owner string, users ...string) string {
	sddl := fmt.Sprintf("O:%sD:P(D;;GA;;;%s)(A;;GA;;;%s)(A;;%s;;;%s)(A;;%s;;;%s)",
		owner, SIDNetwork, owner, pipeClient, SIDSystem, pipeClient, SIDAdministrators)
	for _, u := range users {
		sddl += "(A;;" + pipeClient + ";;;" + u + ")"
	}
	return sddl
}

// WorkerPipeSDDL is the security descriptor of a worker pipe: only the
// worker's service account may connect.
func WorkerPipeSDDL(owner, worker string) string {
	return fmt.Sprintf("O:%sD:P(D;;GA;;;%s)(A;;GA;;;%s)(A;;%s;;;%s)",
		owner, SIDNetwork, owner, pipeClient, worker)
}

// WorkerServiceSDDL is the security descriptor of a worker service (S-20):
// SYSTEM and Administrators have full control, the supervisor may query,
// start, stop and interrogate it, and interactive users may only query.
func WorkerServiceSDDL(supervisor string) string {
	return fmt.Sprintf("D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;%s)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;%s)(A;;LCRPWPLO;;;%s)(A;;CCLCSWLORC;;;%s)",
		SIDSystem, SIDAdministrators, supervisor, SIDInteractive)
}

// Folder descriptors (plan section 4 table, ADR-0006). All are protected, so
// nothing is inherited from %ProgramData%, and OWNER RIGHTS limits whoever
// creates a file to reading its permissions, so a file's creator cannot grant
// itself more.

// ConfigFolderSDDL: SYSTEM and Administrators full, supervisor modify.
func ConfigFolderSDDL(supervisor string) string {
	return fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;FA;;;%s)(A;OICI;%s;;;%s)(A;OICI;RC;;;%s)",
		SIDSystem, SIDAdministrators, fileModify, supervisor, SIDOwnerRights)
}

// SecretsFolderSDDL: SYSTEM full, supervisor modify, nobody else.
func SecretsFolderSDDL(supervisor string) string {
	return fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;%s;;;%s)(A;OICI;RC;;;%s)",
		SIDSystem, fileModify, supervisor, SIDOwnerRights)
}

// LogsFolderSDDL is the parent logs folder: SYSTEM and Administrators full
// (setup creates the log folders inside it), the supervisor read. Each log
// folder inside has its own protected descriptor.
func LogsFolderSDDL(supervisor string) string {
	return fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;FA;;;%s)(A;OICI;FR;;;%s)(A;OICI;RC;;;%s)",
		SIDSystem, SIDAdministrators, supervisor, SIDOwnerRights)
}

// AuditFolderSDDL (S-36): the supervisor may create files in the folder and
// append to them, never rewrite them.
func AuditFolderSDDL(supervisor string) string {
	return fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;FR;;;%s)(A;CI;%s;;;%s)(A;OIIO;%s;;;%s)(A;OICI;RC;;;%s)",
		SIDSystem, SIDAdministrators, dirReadAddFile, supervisor, fileReadAppend, supervisor, SIDOwnerRights)
}

// WorkerLogFolderSDDL: the worker modifies its own log folder; the supervisor
// and Administrators read it.
func WorkerLogFolderSDDL(supervisor, worker string) string {
	return fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;FR;;;%s)(A;OICI;FR;;;%s)(A;OICI;%s;;;%s)(A;OICI;RC;;;%s)",
		SIDSystem, SIDAdministrators, supervisor, fileModify, worker, SIDOwnerRights)
}

// UpdatesFolderSDDL: supervisor modify, Administrators read (S-63).
func UpdatesFolderSDDL(supervisor string) string {
	return fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;FR;;;%s)(A;OICI;%s;;;%s)(A;OICI;RC;;;%s)",
		SIDSystem, SIDAdministrators, fileModify, supervisor, SIDOwnerRights)
}

// DataRootSDDL is %ProgramData%\SoireeHost itself: SYSTEM and Administrators
// full, every SoiréeHost service may list it to reach its own subfolder.
func DataRootSDDL(supervisor, web, tunnel string) string {
	return fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;FA;;;%s)(A;;%s;;;%s)(A;;%s;;;%s)(A;;%s;;;%s)",
		SIDSystem, SIDAdministrators, dirTraverse, supervisor, dirTraverse, web, dirTraverse, tunnel)
}
