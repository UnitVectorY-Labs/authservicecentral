package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/app"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/authorization/compiler"
	engine "github.com/UnitVectorY-Labs/authservicecentral/internal/openfga"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/operational"
)

func Migrate(args []string) error {
	op, err := operational.Parse("migrate", args)
	if err != nil {
		return err
	}
	cfg, err := loadSchema(op.ConfigPath)
	if err != nil {
		return err
	}
	fingerprint, err := cfg.Fingerprint()
	if err != nil {
		return err
	}
	model, err := compiler.Compile(cfg)
	if err != nil {
		return err
	}
	if _, err := app.BuildValidator(cfg, nil); err != nil {
		return fmt.Errorf("validate token sources: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, err := app.OpenDatabase(ctx, op.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate platform database: %w", err)
	}
	if err := engine.MigratePostgres(engine.PostgresConfig{URI: op.DatabaseURL}); err != nil {
		return err
	}
	fga, err := engine.NewPostgres(ctx, engine.PostgresConfig{URI: op.DatabaseURL, Activations: app.ActivationStore{DB: store}})
	if err != nil {
		return err
	}
	defer fga.Close()
	active, changed, err := fga.EnsureModel(ctx, fingerprint, model)
	if err != nil {
		return err
	}
	configuration, _ := json.Marshal(cfg)
	v, err := store.PutConfigurationVersion(ctx, databaseVersion(fingerprint, active.ModelID, configuration))
	if err != nil {
		return err
	}
	if err := store.ActivateConfiguration(ctx, v.ID); err != nil {
		return err
	}
	fmt.Printf("migrations complete (model %s, changed=%t, fingerprint %s)\n", active.ModelID, changed, fingerprint)
	return nil
}
