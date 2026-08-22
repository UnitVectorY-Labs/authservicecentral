package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/migrations"
)

// Store is safe for concurrent use. The caller owns DB and its connection
// pool. This package intentionally does not select a PostgreSQL driver.
type Store struct{ db *sql.DB }

func New(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) DB() *sql.DB { return s.db }

// Open opens a database using a driver registered by the application. Keeping
// the driver outside this package avoids forcing a particular dependency.
func Open(driverName, dataSourceName string) (*Store, error) {
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	return New(db), nil
}

func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return nil
}

func (s *Store) Migrate(ctx context.Context) error { return migrations.Apply(ctx, s.db) }

func (s *Store) Close() error { return s.db.Close() }

type dbtx interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func inTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func jsonOrObject(v []byte) []byte {
	if len(v) == 0 {
		return []byte(`{}`)
	}
	return v
}

func limitOrDefault(n int) int {
	if n <= 0 || n > 1000 {
		return 100
	}
	return n
}
