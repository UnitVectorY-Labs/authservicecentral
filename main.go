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
		fmt.Fprintf(os.Stderr, "usage: authservicecentral <command> [flags]\n\ncommands:\n  run       Start the server\n  migrate   Run database migrations\n  version   Print version\n")
		os.Exit(1)
	}

	var err error

	switch os.Args[1] {
	case "run":
		err = cmd.Run(os.Args[2:])
	case "migrate":
		err = cmd.Migrate(os.Args[2:])
	case "version":
		fmt.Println(Version)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}

	if err != nil {
		log.Fatal(err)
	}
}
