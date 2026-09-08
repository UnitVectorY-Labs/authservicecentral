package cmd

import (
	"fmt"
	"strings"
)

const programName = "authservicecentral"

// HelpRequest describes a help request found in the process argument list.
// An empty Command means that top-level help was requested.
type HelpRequest struct {
	Command string
}

// ParseHelp recognizes the help forms handled by the process dispatcher. It
// intentionally runs before command parsing so that help is useful even when
// the normal command would require configuration, a key, or a database.
func ParseHelp(args []string) (HelpRequest, bool, error) {
	if len(args) == 0 {
		return HelpRequest{}, false, nil
	}

	if isHelpFlag(args[0]) {
		return HelpRequest{}, true, nil
	}

	if args[0] == "help" {
		switch len(args) {
		case 1:
			return HelpRequest{}, true, nil
		case 2:
			if isHelpFlag(args[1]) {
				return HelpRequest{}, true, nil
			}
			return HelpRequest{Command: args[1]}, true, nil
		default:
			if isHelpFlag(args[1]) {
				return HelpRequest{}, true, nil
			}
			if HasHelpFlag(args[2:]) {
				return HelpRequest{Command: args[1]}, true, nil
			}
			return HelpRequest{}, false, fmt.Errorf("help expects one command name, got %d arguments", len(args)-1)
		}
	}

	if HasHelpFlag(args[1:]) {
		return HelpRequest{Command: args[0]}, true, nil
	}
	return HelpRequest{}, false, nil
}

// HasHelpFlag reports whether args contain a standalone help flag. Arguments
// after -- are positional and therefore do not request help.
func HasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func isHelpFlag(arg string) bool {
	return arg == "-h" || arg == "--help"
}

type flagHelp struct {
	name     string
	value    string
	desc     string
	env      string
	fallback string
}

// processFlags mirrors the flags registered by internal/operational.Parse.
// Keep this list in the same order as that parser: it makes command help easy
// to compare with the actual command-line behavior.
var processFlags = []flagHelp{
	{name: "config", value: "PATH", desc: "deployment authorization YAML", env: "SERVICEAUTH_CONFIG", fallback: "serviceauth.yaml"},
	{name: "database-url", value: "URL", desc: "PostgreSQL connection URL", env: "SERVICEAUTH_DATABASE_URL", fallback: "postgres://postgres:postgres@localhost:5432/authservicecentral?sslmode=disable"},
	{name: "issuer", value: "URL", desc: "canonical platform JWT issuer URL", env: "SERVICEAUTH_ISSUER", fallback: "http://localhost:8080"},
	{name: "listen-address", value: "ADDRESS", desc: "HTTP listen address", env: "SERVICEAUTH_LISTEN_ADDRESS", fallback: ":8080"},
	{name: "signing-key-file", value: "PATH", desc: "PEM private signing key", env: "SERVICEAUTH_SIGNING_KEY_FILE", fallback: "empty"},
	{name: "signing-provider", value: "PROVIDER", desc: "signing provider: local or gcp-kms", env: "SERVICEAUTH_SIGNING_PROVIDER", fallback: "local"},
	{name: "gcp-kms-key", value: "RESOURCE", desc: "GCP KMS asymmetric key version resource name", env: "SERVICEAUTH_GCP_KMS_KEY", fallback: "empty"},
	{name: "inactive-signing-key-files", value: "PATHS", desc: "comma-separated inactive local signing keys published for verification", env: "SERVICEAUTH_INACTIVE_SIGNING_KEY_FILES", fallback: "empty"},
	{name: "insecure-management", value: "[=BOOL]", desc: "allow unauthenticated management API (development only)", env: "SERVICEAUTH_INSECURE_MANAGEMENT", fallback: "false"},
	{name: "swagger-ui", value: "[=BOOL]", desc: "serve the Swagger UI and OpenAPI document at the application root", env: "SERVICEAUTH_SWAGGER_UI", fallback: "true"},
	{name: "max-batch-size", value: "N", desc: "maximum checks per authorization request", env: "SERVICEAUTH_MAX_BATCH_SIZE", fallback: "100"},
	{name: "http-timeout", value: "DURATION", desc: "HTTP server read/write timeout", env: "SERVICEAUTH_HTTP_TIMEOUT", fallback: "15s"},
	{name: "shutdown-timeout", value: "DURATION", desc: "graceful HTTP shutdown timeout", env: "SERVICEAUTH_SHUTDOWN_TIMEOUT", fallback: "15s"},
	{name: "reconcile-interval", value: "DURATION", desc: "authorization outbox reconciliation interval", env: "SERVICEAUTH_RECONCILE_INTERVAL", fallback: "2s"},
	{name: "reconcile-batch", value: "N", desc: "authorization outbox reconciliation batch size", env: "SERVICEAUTH_RECONCILE_BATCH", fallback: "100"},
	{name: "metrics", value: "[=BOOL]", desc: "enable the metrics endpoint", env: "SERVICEAUTH_METRICS", fallback: "true"},
	{name: "rate-limit-per-second", value: "RATE", desc: "global HTTP request rate limit; zero disables", env: "SERVICEAUTH_RATE_LIMIT_PER_SECOND", fallback: "0"},
	{name: "rate-limit-burst", value: "N", desc: "global HTTP rate-limit burst; zero disables", env: "SERVICEAUTH_RATE_LIMIT_BURST", fallback: "0"},
	{name: "source", value: "PREFIX", desc: "bootstrap principal token-source prefix", env: "SERVICEAUTH_BOOTSTRAP_SOURCE", fallback: "empty"},
	{name: "subject", value: "SUBJECT", desc: "bootstrap principal subject", env: "SERVICEAUTH_BOOTSTRAP_SUBJECT", fallback: "empty"},
	{name: "role", value: "ROLE", desc: "management-capable role to grant", env: "SERVICEAUTH_BOOTSTRAP_ROLE", fallback: "empty"},
	{name: "management-audience", value: "ID", desc: "management audience ID", env: "SERVICEAUTH_MANAGEMENT_AUDIENCE", fallback: "serviceauth-management"},
	{name: "management-display-name", value: "NAME", desc: "management audience display name", env: "SERVICEAUTH_MANAGEMENT_DISPLAY_NAME", fallback: "ServiceAuth Management"},
	{name: "management-ttl", value: "SECONDS", desc: "management audience token TTL in seconds", env: "SERVICEAUTH_MANAGEMENT_TTL", fallback: "900"},
}

type commandHelp struct {
	name        string
	purpose     string
	usage       []string
	how         string
	flags       bool
	customFlags []flagHelp
}

var commandHelps = map[string]commandHelp{
	"run": {
		name:    "run",
		purpose: "start the HTTP API server",
		usage:   []string{programName + " run [flags]", programName + " api [flags]"},
		how:     "Run migrate first. This command verifies the active database authorization model and starts the API; it does not perform migrations or model activation. The local signing provider requires --signing-key-file, while gcp-kms requires --gcp-kms-key.",
		flags:   true,
	},
	"migrate": {
		name:    "migrate",
		purpose: "apply database migrations and activate the compiled OpenFGA model",
		usage:   []string{programName + " migrate [flags]"},
		how:     "Run this after changing the authorization YAML and before starting run. It validates the schema, migrates PostgreSQL and OpenFGA, then activates the model for the configuration fingerprint.",
		flags:   true,
	},
	"bootstrap": {
		name:    "bootstrap",
		purpose: "create the initial resource-scoped management grant",
		usage:   []string{programName + " bootstrap [flags]"},
		how:     "Run migrate first, then provide --source, --subject, and --role for the principal that should receive management access. The command upserts the management audience and creates an idempotent grant scoped to it.",
		flags:   true,
	},
	"validate": {
		name:    "validate",
		purpose: "strictly validate authorization YAML and print its fingerprint",
		usage:   []string{programName + " validate [flags]"},
		how:     "Use this in a configuration check before migrate. It reads the YAML, compiles the OpenFGA model, validates trusted token sources, and makes no database or network changes.",
		flags:   true,
	},
	"model": {
		name:    "model",
		purpose: "print the deterministic generated OpenFGA model as JSON",
		usage:   []string{programName + " model [flags]"},
		how:     "Pass the same authorization YAML used by migrate. Redirect the JSON output if you need to inspect or archive the generated model, for example: authservicecentral model --config serviceauth.yaml > model.json.",
		flags:   true,
	},
	"doctor": {
		name:    "doctor",
		purpose: "check database, active model, signing key, and trusted issuers",
		usage:   []string{programName + " doctor [flags]"},
		how:     "Run this against a deployed configuration after migrate. It checks the active model and signer and performs remote trust discovery for configured issuers; local signing requires --signing-key-file, while gcp-kms requires --gcp-kms-key.",
		flags:   true,
	},
	"config-docs": {
		name:    "config-docs",
		purpose: "render the validated YAML as browsable static configuration documentation",
		usage:   []string{programName + " config-docs [flags]"},
		how:     "Pass the YAML file and an output directory. The command validates the document, writes deterministic HTML pages, and redacts key material before rendering; the output directory can be served by any static file server.",
		customFlags: []flagHelp{
			{name: "config", value: "PATH", desc: "deployment authorization YAML", env: "SERVICEAUTH_CONFIG", fallback: "serviceauth.yaml"},
			{name: "output-dir", value: "PATH", desc: "directory for generated static HTML", env: "none", fallback: "config-docs"},
			{name: "output", value: "PATH", desc: "alias for --output-dir", env: "none", fallback: "config-docs"},
		},
	},
	"version": {
		name:    "version",
		purpose: "print the build version",
		usage:   []string{programName + " version"},
		how:     "Use this to identify the running build. This command does not read configuration and accepts no process flags.",
	},
}

// Usage returns the top-level command help.
func Usage() string {
	return strings.TrimSpace(`authservicecentral — authorization and token exchange service

Usage:
  authservicecentral <command> [flags]
  authservicecentral help <command>

Commands:
  ctl        Control a running deployment through its public HTTP API
  run        Start the HTTP API server (api is an alias)
  migrate    Apply database migrations and activate the OpenFGA model
  bootstrap  Create the initial resource-scoped management grant
  validate   Validate authorization YAML without changing external state
  model      Print the generated OpenFGA model as JSON
  doctor     Check deployment dependencies and trusted issuers
  config-docs Render safe static HTML documentation from the YAML
  version    Print the build version

Help:
  authservicecentral --help
  authservicecentral run --help
  authservicecentral help migrate

The run, api, migrate, bootstrap, validate, model, and doctor commands accept
the shared process flags. config-docs has its own YAML and output flags. ctl has
remote-client flags documented by authservicecentral help ctl. Each command's
help lists the matching environment variables and fallback values.`)
}

// HelpFor returns detailed help for a command or the top-level command list.
func HelpFor(command string) (string, error) {
	if command == "" || command == "help" {
		return Usage(), nil
	}
	if command == "api" {
		command = "run"
	}
	if command == "ctl" {
		return ctlUsage(), nil
	}

	help, ok := commandHelps[command]
	if !ok {
		return "", fmt.Errorf("unknown command %q", command)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s — %s\n\n", programName+" "+help.name, help.purpose)
	b.WriteString("Usage:\n")
	for _, usage := range help.usage {
		fmt.Fprintf(&b, "  %s\n", usage)
	}
	b.WriteString("\nHow to run:\n  ")
	b.WriteString(help.how)
	b.WriteString("\n")

	if help.flags || len(help.customFlags) > 0 {
		b.WriteString("\nFlags:\n  -h, --help\n      show this command help and exit\n")
		flags := help.customFlags
		if help.flags {
			flags = processFlags
		}
		for _, flag := range flags {
			flagSyntax := "--" + flag.name
			if strings.HasPrefix(flag.value, "[") {
				flagSyntax += flag.value
			} else {
				flagSyntax += " " + flag.value
			}
			fmt.Fprintf(&b, "  %s\n      %s\n      environment: %s (fallback: %s)\n", flagSyntax, flag.desc, flag.env, flag.fallback)
		}
		b.WriteString("\nEnvironment values are read before flags. Empty values use the fallback where one is defined; typed values that cannot be parsed also use their fallback, while values that fail command validation are errors. Invalid flag values are errors. Durations use Go syntax such as 500ms, 15s, or 2m.")
	}

	return strings.TrimSpace(b.String()), nil
}
