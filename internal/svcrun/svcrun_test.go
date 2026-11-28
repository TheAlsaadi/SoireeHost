package svcrun

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
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
	for dep := range strings.FieldsSeq(string(out)) {
		if strings.HasPrefix(dep, caddyPackage) {
			t.Fatalf("svcrun depends on %s, so Caddy's init could run first", dep)
		}
	}
}

// A stop control cancels the role's context; serve reports the role's result
// to serviceMain, returns once the dispatcher has, and leaves nothing
// running (R-24, GOE-20). The state has no status handle, so the status
// reports it makes are refused by Windows and ignored.
func TestServeStopsOnControl(t *testing.T) {
	testutil.CheckGoroutines(t)
	d := &dispatcherState{
		controls: make(chan uint32, 8),
		result:   make(chan [2]uint32, 1),
		stopped:  make(chan error, 1),
	}
	failed := errors.New("role failed")
	for _, want := range []error{nil, failed} {
		d.controls <- windows.SERVICE_CONTROL_STOP
		d.stopped <- nil
		done := make(chan error, 1)
		go func() {
			done <- d.serve(false, func(ctx context.Context) error {
				<-ctx.Done()
				return want
			})
		}()
		select {
		case err := <-done:
			if !errors.Is(err, want) {
				t.Fatalf("serve returned %v, want %v", err, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("serve did not return after a stop control")
		}
		wantCode := [2]uint32{}
		if want != nil {
			wantCode = [2]uint32{1, 1}
		}
		if got := <-d.result; got != wantCode {
			t.Fatalf("result for serviceMain %v, want %v", got, wantCode)
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
