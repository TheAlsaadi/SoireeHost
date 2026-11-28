package winsec

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileStandardInfo is FILE_STANDARD_INFO (winbase.h), which x/sys/windows
// does not define. Querying it needs no access right on the handle.
type fileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  uint8
	Directory      uint8
}

// fileAttributeTagInfo is FILE_ATTRIBUTE_TAG_INFO (winbase.h). Querying it
// needs FILE_READ_ATTRIBUTES.
type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

func standardInfo(h windows.Handle) (fileStandardInfo, error) {
	var fi fileStandardInfo
	// #nosec G103 G115 -- the documented FILE_STANDARD_INFO output buffer and its fixed size
	err := windows.GetFileInformationByHandleEx(h, windows.FileStandardInfo, (*byte)(unsafe.Pointer(&fi)), uint32(unsafe.Sizeof(fi)))
	return fi, err
}

func attributeTagInfo(h windows.Handle) (fileAttributeTagInfo, error) {
	var fi fileAttributeTagInfo
	// #nosec G103 G115 -- the documented FILE_ATTRIBUTE_TAG_INFO output buffer and its fixed size
	err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&fi)), uint32(unsafe.Sizeof(fi)))
	return fi, err
}

// reparseNameSurrogate is the tag bit that marks a reparse point standing
// for another named object: a junction, mount point or symbolic link
// (IsReparseTagNameSurrogate, winnt.h). Other reparse points (cloud files,
// deduplicated or compressed files) are the file itself.
const reparseNameSurrogate = 0x20000000

// isLink reports whether fi describes a link, junction or mount point.
func isLink(fi fileAttributeTagInfo) bool {
	return fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && fi.ReparseTag&reparseNameSurrogate != 0
}
