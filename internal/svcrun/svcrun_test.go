package svcrun

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

const (
	thisPackage  = "github.com/TheAlsaadi/SoireeHost/internal/svcrun"
	caddyPackage = "github.com/caddyserver/caddy/v2"
)

// This package must claim the service dispatcher before Caddy's init() does
// (see the dispatcher comment). That holds only while this package sorts
// before Caddy by import path and does not depend on Caddy at all.
func TestInitRunsBeforeCaddy(t *testing.T) {
	if thisPackage >= caddyPackage {
		t.Fatalf("%s no longer sorts before %s", thisPackage, caddyPackage)
	}
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasPrefix(dep, caddyPackage) {
			t.Fatalf("svcrun depends on %s, so Caddy's init could run first", dep)
		}
	}
}

func TestRunOutsideAService(t *testing.T) {
	if dispatcher.isService {
		t.Skip("running as a service")
	}
	err := Run("x", false, func(context.Context) error { return nil })
	if !errors.Is(err, ErrNotService) {
		t.Fatalf("err = %v", err)
	}
}
