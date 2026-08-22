package cmd

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/app"
	engine "github.com/UnitVectorY-Labs/authservicecentral/internal/openfga"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/operational"
)

func Doctor(args []string) error {
	op, err := operational.Parse("doctor", args)
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
	active, err := fga.VerifyFingerprint(ctx, fingerprint)
	if err != nil {
		return err
	}
	signingBundle, err := app.BuildSigning(ctx, op)
	if err != nil {
		return err
	}
	defer signingBundle.Close()
	if _, err := signingBundle.Active.PublicJWK(ctx); err != nil {
		return err
	}
	client := &http.Client{Timeout: op.HTTPTimeout}
	if _, err := app.BuildValidator(cfg, client); err != nil {
		return err
	}
	if err := app.ProbeRemoteTrust(ctx, cfg, client); err != nil {
		return err
	}
	fmt.Printf("healthy (database, signing key, trusted issuers, OpenFGA model %s, fingerprint %s)\n", active.ModelID, fingerprint)
	return nil
}
