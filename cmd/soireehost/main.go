// Command soireehost is the whole SoiréeHost application. The first argument
// selects the role; with no argument it opens the control panel.
package main

import (
	"fmt"
	"os"

	"github.com/TheAlsaadi/SoireeHost/internal/gui"
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

func run(args []string) int {
	r, err := parseRole(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "soireehost:", err)
		return 2
	}
	switch r {
	case roleGUI:
		if err := gui.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "soireehost:", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "soireehost: the %s role is not built yet\n", r)
		return 2
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}
