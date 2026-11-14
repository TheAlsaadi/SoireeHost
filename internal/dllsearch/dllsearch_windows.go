// Package dllsearch restricts where this process loads DLLs from to System32
// (S-24) from a package init, before any other SoiréeHost package and before
// any third-party package that loads a DLL while it initialises. Wails' w32
// package loads uxtheme.dll by bare name in its init, which runs before main
// in every role, so a restriction applied only in main came too late (review
// finding R-20).
//
// Go initialises packages in import-path order once their dependencies are
// done. This package depends on nothing but syscall, so it is ready as soon
// as syscall is, and its path, github.com/TheAlsaadi/..., sorts before
// github.com/wailsapp/... and every other module this program links that
// could load a DLL at init. main still calls winsec.RestrictDLLSearch and
// checks Err, so a failure here stops the program.
package dllsearch

import "syscall"

// loadLibrarySearchSystem32 is LOAD_LIBRARY_SEARCH_SYSTEM32 (libloaderapi.h).
const loadLibrarySearchSystem32 = 0x00000800

// Err is the error from restricting the search, or nil.
var Err error

func init() {
	// kernel32 is a KnownDLL and is already loaded into every process, so
	// naming it cannot load a planted copy.
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("SetDefaultDllDirectories")
	if err := proc.Find(); err != nil {
		Err = err
		return
	}
	if r, _, err := proc.Call(loadLibrarySearchSystem32); r == 0 {
		Err = err
	}
}
