package main

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/cmd"
)

// Version is the application version, injected at build time via ldflags
var Version = "dev"

func main() {
	// Set the build version from the build info if not set by the build system
	if Version == "dev" || Version == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				Version = bi.Main.Version
			}
		}
	}

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, cmd.Usage())
		os.Exit(1)
	}

	var err error

	switch os.Args[1] {
	case "run", "api":
		err = cmd.API(os.Args[2:])
	case "migrate":
		err = cmd.Migrate(os.Args[2:])
	case "bootstrap":
		err = cmd.Bootstrap(os.Args[2:])
	case "validate":
		err = cmd.Validate(os.Args[2:])
	case "model":
		err = cmd.Model(os.Args[2:])
	case "doctor":
		err = cmd.Doctor(os.Args[2:])
	case "version":
		fmt.Println(Version)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s\n", os.Args[1], cmd.Usage())
		os.Exit(1)
	}

	if err != nil {
		log.Fatal(err)
	}
}
