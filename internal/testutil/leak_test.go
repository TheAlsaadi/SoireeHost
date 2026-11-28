package testutil

import (
	"strings"
	"testing"
	"time"
)

// The leak check reports a goroutine that is stuck and forgets it once it
// ends (GOE-20).
func TestLeakedFindsAStuckGoroutine(t *testing.T) {
	before := goroutines()
	release, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		<-release
	}()
	left := leaked(before, 100*time.Millisecond)
	if len(left) != 1 || !strings.Contains(left[0], "TestLeakedFindsAStuckGoroutine") {
		t.Errorf("stuck goroutine not reported: %q", left)
	}
	close(release)
	<-done
	if left := leaked(before, 5*time.Second); len(left) != 0 {
		t.Errorf("ended goroutine still reported: %q", left)
	}
}
