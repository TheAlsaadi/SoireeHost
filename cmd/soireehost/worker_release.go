//go:build production

package main

import (
	"fmt"
	"os"
)

// runWorker in release builds will run under the SoiréeHost service and take
// its config from the supervisor's named pipe (Phase 2). Until then it does
// nothing.
func runWorker([]string) int {
	fmt.Fprintln(os.Stderr, "soireehost: the worker role is started by the SoiréeHost service, which is not built yet")
	return 2
}
