package testutil

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// modulePrefix marks a stack frame, or a "created by" line, of this module.
const modulePrefix = "github.com/TheAlsaadi/SoireeHost/"

// leakWait is how long a stopped component's goroutines get to end.
const leakWait = 10 * time.Second

// CheckGoroutines fails the test if a goroutine that runs this module's code,
// or was started by it, began after this call and is still there when the
// test ends (review finding GOE-20, R-24). Call it first in a test: cleanups
// run last-in first-out, so the check then runs after everything the test
// started has been told to stop. Goroutines of libraries alone are ignored
// (Caddy keeps some for the life of the process). Not for parallel tests.
func CheckGoroutines(t testing.TB) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		if left := leaked(before, leakWait); len(left) > 0 {
			t.Errorf("%d goroutine(s) still running %v after the test ended:\n\n%s",
				len(left), leakWait, strings.Join(left, "\n\n"))
		}
	})
}

// goroutines returns the stack of every goroutine but the caller's, by id.
func goroutines() map[string]string {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	all := map[string]string{}
	// the caller's goroutine is always listed first
	for _, s := range strings.Split(string(buf), "\n\n")[1:] {
		if f := strings.Fields(s); len(f) > 1 && f[0] == "goroutine" {
			all[f[1]] = strings.TrimSpace(s)
		}
	}
	return all
}

// leaked waits up to wait for this module's new goroutines to end and returns
// the stacks of those that did not.
func leaked(before map[string]string, wait time.Duration) []string {
	deadline := time.Now().Add(wait)
	for {
		var left []string
		for id, stack := range goroutines() {
			if _, old := before[id]; !old && strings.Contains(stack, modulePrefix) {
				left = append(left, stack)
			}
		}
		if len(left) == 0 || time.Now().After(deadline) {
			return left
		}
		time.Sleep(20 * time.Millisecond)
	}
}
