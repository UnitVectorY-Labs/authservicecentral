package openfga

import (
	"context"
	"fmt"
	"time"

	"github.com/openfga/openfga/pkg/storage/migrate"
	fgapostgres "github.com/openfga/openfga/pkg/storage/postgres"
	"github.com/openfga/openfga/pkg/storage/sqlcommon"
)

type PostgresConfig struct {
	URI          string
	StoreName    string
	Activations  ActivationStore
	MaxOpenConns int
	MinOpenConns int
	PingTimeout  time.Duration
}

// MigratePostgres applies the migrations embedded in the pinned OpenFGA
// module through its supported migration library.
func MigratePostgres(cfg PostgresConfig) error {
	if cfg.URI == "" {
		return fmt.Errorf("migrate OpenFGA: PostgreSQL URI is required")
	}
	timeout := cfg.PingTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return migrate.RunMigrations(migrate.MigrationConfig{Engine: "postgres", URI: cfg.URI, Timeout: 30 * time.Second, PingTimeout: timeout})
}

// NewPostgres initializes a PostgreSQL-backed embedded OpenFGA engine. Schema
// migration is deliberately explicit via MigratePostgres.
func NewPostgres(ctx context.Context, cfg PostgresConfig) (*Engine, error) {
	if cfg.URI == "" {
		return nil, fmt.Errorf("initialize OpenFGA: PostgreSQL URI is required")
	}
	opts := []sqlcommon.DatastoreOption{}
	if cfg.MaxOpenConns > 0 {
		opts = append(opts, sqlcommon.WithMaxOpenConns(cfg.MaxOpenConns))
	}
	if cfg.MinOpenConns > 0 {
		opts = append(opts, sqlcommon.WithMinOpenConns(cfg.MinOpenConns))
	}
	if cfg.PingTimeout > 0 {
		opts = append(opts, sqlcommon.WithPingTimeout(cfg.PingTimeout))
	}
	ds, err := fgapostgres.New(cfg.URI, sqlcommon.NewConfig(opts...))
	if err != nil {
		return nil, fmt.Errorf("initialize OpenFGA PostgreSQL datastore: %w", err)
	}
	e, err := New(ctx, Options{Datastore: ds, StoreName: cfg.StoreName, Activations: cfg.Activations})
	if err != nil {
		ds.Close()
		return nil, err
	}
	return e, nil
}
