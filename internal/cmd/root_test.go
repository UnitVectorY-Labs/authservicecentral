package cmd

import (
	"strings"
	"testing"
)

func TestParseHelp(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		command   string
		handled   bool
		expectErr bool
	}{
		{name: "no help", args: []string{"validate", "--config", "serviceauth.yaml"}},
		{name: "top long", args: []string{"--help"}, handled: true},
		{name: "top short", args: []string{"-h"}, handled: true},
		{name: "help command", args: []string{"help", "migrate"}, command: "migrate", handled: true},
		{name: "help command with flag", args: []string{"help", "doctor", "--help"}, command: "doctor", handled: true},
		{name: "subcommand long", args: []string{"run", "--help"}, command: "run", handled: true},
		{name: "subcommand short", args: []string{"api", "-h"}, command: "api", handled: true},
		{name: "help after end marker", args: []string{"run", "--", "--help"}},
		{name: "malformed help", args: []string{"help", "run", "extra"}, expectErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, handled, err := ParseHelp(test.args)
			if test.expectErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if handled != test.handled || request.Command != test.command {
				t.Fatalf("got request=%#v handled=%t, want command=%q handled=%t", request, handled, test.command, test.handled)
			}
		})
	}
}

func TestHelpForCommandsIncludesPurposeUsageAndEnvironmentPairings(t *testing.T) {
	for _, name := range []string{"run", "api", "migrate", "bootstrap", "validate", "model", "doctor", "config-docs", "version"} {
		t.Run(name, func(t *testing.T) {
			help, err := HelpFor(name)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(help, "How to run:") || !strings.Contains(help, "Usage:") {
				t.Fatalf("help is missing purpose/how-to-run content:\n%s", help)
			}
			if name != "version" && name != "config-docs" {
				for _, flag := range processFlags {
					if !strings.Contains(help, "--"+flag.name) || !strings.Contains(help, flag.env) {
						t.Errorf("help is missing flag/environment pairing for --%s/%s", flag.name, flag.env)
					}
				}
			}
			if name == "config-docs" {
				for _, flag := range []string{"--config", "SERVICEAUTH_CONFIG", "--output-dir", "--output"} {
					if !strings.Contains(help, flag) {
						t.Errorf("config-docs help is missing %q", flag)
					}
				}
			}
		})
	}
}

func TestHelpForUnknownCommand(t *testing.T) {
	if _, err := HelpFor("not-a-command"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUsageListsAliasesAndHelpForms(t *testing.T) {
	usage := Usage()
	for _, want := range []string{"authservicecentral <command> [flags]", "authservicecentral help <command>", "api is an alias", "config-docs", "authservicecentral run --help"} {
		if !strings.Contains(usage, want) {
			t.Errorf("usage does not contain %q:\n%s", want, usage)
		}
	}
}
