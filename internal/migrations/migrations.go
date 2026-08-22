// Package migrations applies the embedded, application-owned PostgreSQL schema.
// It deliberately does not manage OpenFGA's private schema.
package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed *.sql
var files embed.FS

type migration struct {
	version int64
	name    string
	body    string
	sum     string
}

// Apply applies all unapplied migrations in order. Each migration is atomic,
// recorded with a checksum, and serialized across concurrent application
// processes with a PostgreSQL advisory transaction lock.
func Apply(ctx context.Context, db *sql.DB) error {
	ms, err := load()
	if err != nil {
		return err
	}
	for _, m := range ms {
		if err := applyOne(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

func applyOne(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", m.name, err)
	}
	defer tx.Rollback()

	// A fixed application-specific key prevents concurrent migrators while not
	// interfering with OpenFGA's own migration mechanism.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(738114727045217)`); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS platform`); err != nil {
		return fmt.Errorf("create platform schema: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform.schema_migrations (
		version bigint PRIMARY KEY,
		name text NOT NULL,
		checksum text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	var checksum string
	err = tx.QueryRowContext(ctx, `SELECT checksum FROM platform.schema_migrations WHERE version = $1`, m.version).Scan(&checksum)
	switch {
	case err == nil:
		if checksum != m.sum {
			return fmt.Errorf("migration %s checksum changed: database=%s embedded=%s", m.name, checksum, m.sum)
		}
		return tx.Commit()
	case err != sql.ErrNoRows:
		return fmt.Errorf("inspect migration %s: %w", m.name, err)
	}

	if _, err := tx.ExecContext(ctx, m.body); err != nil {
		return fmt.Errorf("apply migration %s: %w", m.name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO platform.schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
		m.version, m.name, m.sum); err != nil {
		return fmt.Errorf("record migration %s: %w", m.name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", m.name, err)
	}
	return nil
}

func load() ([]migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	var out []migration
	seen := make(map[int64]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("migration %q must begin with a numeric version and underscore", entry.Name())
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migration %q has invalid version", entry.Name())
		}
		if prior, exists := seen[version]; exists {
			return nil, fmt.Errorf("migrations %q and %q have duplicate version %d", prior, entry.Name(), version)
		}
		body, err := files.ReadFile(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		hash := sha256.Sum256(body)
		out = append(out, migration{version: version, name: entry.Name(), body: string(body), sum: hex.EncodeToString(hash[:])})
		seen[version] = entry.Name()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}
