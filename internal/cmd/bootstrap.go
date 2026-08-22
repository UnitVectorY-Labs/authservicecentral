package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/app"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
	engine "github.com/UnitVectorY-Labs/authservicecentral/internal/openfga"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/operational"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/service"
)

func Bootstrap(args []string) error {
	op, err := operational.Parse("bootstrap", args)
	if err != nil {
		return err
	}
	cfg, err := loadSchema(op.ConfigPath)
	if err != nil {
		return err
	}
	if !hasPrincipalSource(cfg, op.BootstrapSource) {
		return fmt.Errorf("bootstrap source %q is not a configured identity prefix", op.BootstrapSource)
	}
	if err := validateBootstrapRole(cfg, op.BootstrapRole); err != nil {
		return err
	}
	fingerprint, err := cfg.Fingerprint()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, err := app.OpenDatabase(ctx, op.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	fga, err := engine.NewPostgres(ctx, engine.PostgresConfig{URI: op.DatabaseURL, Activations: app.ActivationStore{DB: store}})
	if err != nil {
		return err
	}
	defer fga.Close()
	if _, err := fga.VerifyFingerprint(ctx, fingerprint); err != nil {
		return fmt.Errorf("verify active authorization model: %w", err)
	}
	domain, err := service.New(store, cfg, app.ServiceEngine{Engine: fga})
	if err != nil {
		return err
	}
	operation := bootstrapOperationID(op)
	audience, err := domain.PutAudience(ctx, service.Mutation{OperationID: operation + ":audience", Actor: "bootstrap:" + op.BootstrapSource + ":" + op.BootstrapSubject}, database.Audience{ID: op.ManagementAudience, DisplayName: op.ManagementDisplayName, TokenTTLSeconds: op.ManagementTTL, DelegationMode: database.DelegationDisabled})
	if err != nil {
		return fmt.Errorf("create management audience: %w", err)
	}
	grant := database.Grant{ID: bootstrapGrantID(op), Subject: database.PrincipalSubject(op.BootstrapSource, op.BootstrapSubject), Role: op.BootstrapRole, Resource: database.ResourceRef{Type: "audience", ID: audience.ID}}
	created, err := domain.CreateGrant(ctx, service.Mutation{OperationID: operation + ":grant", Actor: "bootstrap:" + op.BootstrapSource + ":" + op.BootstrapSubject}, service.CreateGrantRequest{Grant: grant})
	if err != nil {
		return fmt.Errorf("create bootstrap grant: %w", err)
	}
	if err := app.DrainOutbox(ctx, domain, op.ReconcileBatch, 3); err != nil {
		return fmt.Errorf("reconcile bootstrap authorization: %w", err)
	}
	fmt.Printf("bootstrap complete (principal %s:%s, role %s, audience %s, grant %s)\n", op.BootstrapSource, op.BootstrapSubject, op.BootstrapRole, audience.ID, created.ID)
	return nil
}

func validateBootstrapRole(cfg *config.Config, roleName string) error {
	role, ok := cfg.Roles[roleName]
	if !ok {
		return fmt.Errorf("bootstrap role %q is not configured", roleName)
	}
	for _, name := range role.Permissions {
		permission, exists := cfg.Permissions[name]
		if exists && strings.HasPrefix(name, "management.") && slices.Contains(permission.Resources, "audience") {
			return nil
		}
	}
	return fmt.Errorf("bootstrap role %q has no management.* permission applicable to audience", roleName)
}

func hasPrincipalSource(cfg *config.Config, source string) bool {
	for _, definition := range cfg.TokenSources {
		if definition.Identity.Prefix == source {
			return true
		}
	}
	return false
}

func bootstrapOperationID(op operational.Config) string { return "bootstrap:" + bootstrapDigest(op) }
func bootstrapGrantID(op operational.Config) string     { return "bootstrap-" + bootstrapDigest(op) }
func bootstrapDigest(op operational.Config) string {
	sum := sha256.Sum256([]byte(op.BootstrapSource + "\x00" + op.BootstrapSubject + "\x00" + op.BootstrapRole + "\x00" + op.ManagementAudience))
	return hex.EncodeToString(sum[:16])
}
