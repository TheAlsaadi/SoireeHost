// Command pecheck fails unless a Windows executable has the exploit
// mitigations S-24 requires: ASLR (dynamic base), high-entropy ASLR and DEP.
//
//	go run ./build/pecheck bin/soireehost.exe
package main

import (
	"debug/pe"
	"errors"
	"fmt"
	"os"
)

// DllCharacteristics flags from the PE/COFF specification.
const (
	highEntropyVA = 0x0020 // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
	dynamicBase   = 0x0040 // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (ASLR)
	nxCompat      = 0x0100 // IMAGE_DLLCHARACTERISTICS_NX_COMPAT (DEP)
)

var required = []struct {
	flag uint16
	name string
}{
	{dynamicBase, "ASLR (DYNAMIC_BASE)"},
	{highEntropyVA, "high-entropy ASLR (HIGH_ENTROPY_VA)"},
	{nxCompat, "DEP (NX_COMPAT)"},
}

// check returns the names of required mitigations missing from path.
func check(path string) ([]string, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return nil, errors.New("not a 64-bit PE image")
	}
	var missing []string
	for _, r := range required {
		if oh.DllCharacteristics&r.flag == 0 {
			missing = append(missing, r.name)
		}
	}
	return missing, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pecheck <file.exe>")
		os.Exit(2)
	}
	missing, err := check(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "pecheck:", err)
		os.Exit(1)
	}
	if len(missing) > 0 {
		for _, m := range missing {
			fmt.Fprintln(os.Stderr, "pecheck: missing", m)
		}
		os.Exit(1)
	}
	fmt.Println("pecheck: ASLR, high-entropy ASLR and DEP are enabled")
}
