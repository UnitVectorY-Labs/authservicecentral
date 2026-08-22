package cmd

import (
	"testing"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/operational"
)

func bootstrapConfig() *config.Config {
	return &config.Config{TokenSources: map[string]config.TokenSource{"corp": {Identity: config.Identity{Prefix: "corp"}}}, Permissions: map[string]config.Permission{
		"management.grants.write": {Resources: []string{"audience"}}, "document.read": {Resources: []string{"document"}},
	}, Roles: map[string]config.Role{"admin": {Permissions: []string{"management.grants.write"}}, "viewer": {Permissions: []string{"document.read"}}}}
}

func TestValidateBootstrapRole(t *testing.T) {
	cfg := bootstrapConfig()
	if err := validateBootstrapRole(cfg, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := validateBootstrapRole(cfg, "viewer"); err == nil {
		t.Fatal("expected non-management role rejection")
	}
	if err := validateBootstrapRole(cfg, "missing"); err == nil {
		t.Fatal("expected unknown role rejection")
	}
	if !hasPrincipalSource(cfg, "corp") || hasPrincipalSource(cfg, "unknown") {
		t.Fatal("source validation failed")
	}
}

func TestValidateBootstrapRoleAcceptsConfiguredManagementPermission(t *testing.T) {
	cfg := bootstrapConfig()
	cfg.Permissions["platform.audiences.admin"] = config.Permission{Resources: []string{"audience"}}
	cfg.Roles["admin"] = config.Role{Permissions: []string{"platform.audiences.admin"}}
	cfg.Management.Permissions.Audiences.Write = "platform.audiences.admin"
	if err := validateBootstrapRole(cfg, "admin"); err != nil {
		t.Fatalf("custom management permission was rejected: %v", err)
	}
}

func TestBootstrapIdentifiersAreStableAndScoped(t *testing.T) {
	op := operational.Config{BootstrapSource: "corp", BootstrapSubject: "alice", BootstrapRole: "admin", ManagementAudience: "serviceauth-management"}
	if bootstrapGrantID(op) != bootstrapGrantID(op) {
		t.Fatal("grant ID is not stable")
	}
	changed := op
	changed.BootstrapSubject = "bob"
	if bootstrapGrantID(op) == bootstrapGrantID(changed) {
		t.Fatal("grant IDs collide across principals")
	}
}
