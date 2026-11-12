// Command soireehost is the whole SoiréeHost application. The first argument
// selects the role; with no argument it opens the control panel.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/TheAlsaadi/SoireeHost/internal/gui"
	"github.com/TheAlsaadi/SoireeHost/internal/setup"
	"github.com/TheAlsaadi/SoireeHost/internal/supervisor"
	"github.com/TheAlsaadi/SoireeHost/internal/svcrun"
	"github.com/TheAlsaadi/SoireeHost/internal/tunnel"
	"github.com/TheAlsaadi/SoireeHost/internal/version"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
	"github.com/TheAlsaadi/SoireeHost/internal/worker"
)

// role identifies which part of the application this process runs as.
type role string

const (
	roleGUI     role = "gui"
	roleService role = "service"
	roleWorker  role = "worker"
	roleTunnel  role = "tunnel"
	roleSetup   role = "setup"
)

// parseRole picks the role from the command-line arguments (without the
// program name). Unknown roles are an error; nothing guesses.
func parseRole(args []string) (role, error) {
	if len(args) == 0 {
		return roleGUI, nil
	}
	switch r := role(args[0]); r {
	case roleGUI, roleService, roleWorker, roleTunnel, roleSetup:
		return r, nil
	default:
		return "", fmt.Errorf("unknown role %q", args[0])
	}
}

// exitCode turns a role's result into the process exit code: 0 for success,
// 2 for a role started the wrong way, 1 for anything else.
func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, svcrun.ErrNotService):
		fmt.Fprintln(os.Stderr, "soireehost:", err)
		return 2
	default:
		fmt.Fprintln(os.Stderr, "soireehost:", err)
		return 1
	}
}

func run(args []string) int {
	r, err := parseRole(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "soireehost:", err)
		return 2
	}
	// S-24: every role loads DLLs from System32 only.
	if err := winsec.RestrictDLLSearch(); err != nil {
		fmt.Fprintln(os.Stderr, "soireehost:", err)
		return 1
	}
	v := version.Current()
	switch r {
	case roleGUI:
		return exitCode(gui.Run())
	case roleService:
		return exitCode(supervisor.RunService(v))
	case roleWorker:
		return runWorker(args[1:])
	case roleTunnel:
		return exitCode(tunnel.RunService(v))
	case roleSetup:
		return runSetup(args[1:])
	}
	return 2
}

// runWebWorker runs the web worker service.
func runWebWorker() int { return exitCode(worker.RunService(version.Current())) }

func runSetup(args []string) int {
	usage := func() int {
		fmt.Fprintln(os.Stderr, "usage: soireehost setup install | uninstall [--purge]")
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	l, err := setup.DefaultLayout()
	if err != nil {
		return exitCode(err)
	}
	switch {
	case args[0] == "install" && len(args) == 1:
		return exitCode(setup.Install(l))
	case args[0] == "uninstall" && len(args) == 1:
		return exitCode(setup.Uninstall(l, false))
	case args[0] == "uninstall" && len(args) == 2 && args[1] == "--purge":
		return exitCode(setup.Uninstall(l, true))
	}
	return usage()
}

func main() {
	os.Exit(run(os.Args[1:]))
}
