package cmd

// API and Migrate are wired by their domain-specific files. Keeping the root
// dispatcher small makes every command straightforward to exercise in tests.
func Usage() string {
	return "usage: authservicecentral <command> [flags]\n\ncommands:\n  run       Start the API server\n  api       Alias for run\n  migrate   Migrate database and authorization model\n  bootstrap Create the initial management grant\n  validate  Validate configuration without changes\n  model     Print the generated OpenFGA model\n  doctor    Check deployment dependencies\n  version   Print version"
}
