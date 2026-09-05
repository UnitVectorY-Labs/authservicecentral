package main

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/api"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/cmd"
)

// canonicalOpenAPISpec is the contract served by the production Swagger UI.
// Keeping it in the executable prevents the API reference from depending on
// the process working directory or an external mounted file.
//
//go:embed openapi.yaml
var canonicalOpenAPISpec []byte

// Version is the application version, injected at build time via ldflags
var Version = "dev"

func main() {
	api.SetOpenAPISpec(canonicalOpenAPISpec)

	// Set the build version from the build info if not set by the build system
	if Version == "dev" || Version == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				Version = bi.Main.Version
			}
		}
	}

	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
}

func dispatch(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, cmd.Usage())
		return 1
	}
	if args[0] == "ctl" {
		return cmd.CTL(args[1:], os.Stdin, stdout, stderr)
	}

	request, handled, parseErr := cmd.ParseHelp(args)
	if parseErr != nil {
		return usageError(stderr, parseErr)
	}
	if handled {
		help, err := cmd.HelpFor(request.Command)
		if err != nil {
			return usageError(stderr, err)
		}
		fmt.Fprintln(stdout, help)
		return 0
	}

	var commandErr error
	switch args[0] {
	case "run", "api":
		commandErr = cmd.API(args[1:])
	case "migrate":
		commandErr = cmd.Migrate(args[1:])
	case "bootstrap":
		commandErr = cmd.Bootstrap(args[1:])
	case "validate":
		commandErr = cmd.Validate(args[1:])
	case "model":
		commandErr = cmd.Model(args[1:])
	case "doctor":
		commandErr = cmd.Doctor(args[1:])
	case "config-docs":
		commandErr = cmd.ConfigDocs(args[1:])
	case "version":
		if len(args) != 1 {
			return usageError(stderr, fmt.Errorf("version does not accept arguments"))
		}
		fmt.Fprintln(stdout, Version)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n%s\n", args[0], cmd.Usage())
		return 1
	}

	if commandErr != nil {
		fmt.Fprintln(stderr, commandErr)
		return 1
	}
	return 0
}

func usageError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "error: %s\n\n%s\n", err, cmd.Usage())
	return 1
}
