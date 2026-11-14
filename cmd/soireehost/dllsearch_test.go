package main

// R-20 (S-24, docs/reviews/2026-11-12-skills-review.md): Wails' w32 package
// loads uxtheme.dll by bare name in its package init, before main runs. The
// test binary links the same packages as soireehost.exe, so it runs the same
// inits. The test puts a copy of System32\uxtheme.dll beside the binary,
// runs the binary again as a child, and checks that the child loaded
// uxtheme.dll from System32, not the copy.

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/dllsearch"
)

const r20ChildEnv = "SOIREEHOST_R20_CHILD"

func loadedModule(t *testing.T, base string) string {
	t.Helper()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(snap) //nolint:errcheck // test
	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	for err = windows.Module32First(snap, &me); err == nil; err = windows.Module32Next(snap, &me) {
		if p := windows.UTF16ToString(me.ExePath[:]); strings.EqualFold(filepath.Base(p), base) {
			return p
		}
	}
	return ""
}

func TestPlantedDLLNotLoadedBeforeMain(t *testing.T) {
	if os.Getenv(r20ChildEnv) == "1" {
		if dllsearch.Err != nil {
			t.Fatalf("restricting DLL search: %v", dllsearch.Err)
		}
		if p := loadedModule(t, "uxtheme.dll"); p != "" {
			t.Logf("UXTHEME=%s", p)
		}
		return
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(filepath.Dir(self), "uxtheme.dll")
	if err := copyFile(filepath.Join(sys, "uxtheme.dll"), planted); err != nil {
		t.Skipf("cannot place a copy of uxtheme.dll beside the test binary: %v", err)
	}
	defer func() { _ = os.Remove(planted) }()

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "-test.run=^TestPlantedDLLNotLoadedBeforeMain$", "-test.count=1", "-test.v") //nolint:gosec // G204: re-running this test binary
	cmd.Env = append(os.Environ(), r20ChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if _, p, ok := strings.Cut(line, "UXTHEME="); ok {
			p = strings.TrimSpace(p)
			if !strings.EqualFold(filepath.Dir(p), sys) {
				t.Fatalf("uxtheme.dll was loaded from %s, not %s", p, sys)
			}
			return
		}
	}
	t.Logf("uxtheme.dll is not loaded in the child; nothing was loaded from beside the binary")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- System32 path
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst) // #nosec G304 -- beside the test binary
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
