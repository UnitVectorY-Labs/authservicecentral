package migrations

import (
	"strings"
	"testing"
)

func TestEmbeddedMigrationsAreOrderedAndWellFormed(t *testing.T) {
	ms, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 {
		t.Fatal("no embedded migrations")
	}
	for i, m := range ms {
		if i > 0 && ms[i-1].version >= m.version {
			t.Fatalf("versions are not increasing: %d then %d", ms[i-1].version, m.version)
		}
		if len(m.sum) != 64 || strings.TrimSpace(m.body) == "" {
			t.Fatalf("invalid embedded migration %q", m.name)
		}
	}
}

func TestInitialMigrationKeepsOpenFGASeparate(t *testing.T) {
	ms, err := load()
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ToLower(ms[0].body)
	for _, want := range []string{
		"platform.resources", "platform.resource_relationships", "platform.group_memberships",
		"platform.grants", "platform.authorization_operations", "platform.audit_events",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("migration missing %q", want)
		}
	}
	if strings.Contains(body, "openfga.") {
		t.Error("application migration must not manipulate OpenFGA schema")
	}
}
