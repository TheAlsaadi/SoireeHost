package gui

import (
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/version"
)

func TestVersionBinding(t *testing.T) {
	orig := version.Version
	t.Cleanup(func() { version.Version = orig })

	version.Version = "2.0.1"
	if got := (AppService{}).Version(); got != "2.0.1" {
		t.Errorf("Version() = %q, want 2.0.1", got)
	}
}
