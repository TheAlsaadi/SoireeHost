//go:build production

package main

// runWorker runs the web worker service. Release builds take no arguments:
// the supervisor hands the worker its config over a named pipe.
func runWorker(args []string) int {
	if len(args) != 0 {
		return 2
	}
	return runWebWorker()
}
