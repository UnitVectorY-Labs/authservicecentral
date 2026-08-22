package database

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *Store) PutConfigurationVersion(ctx context.Context, v ConfigurationVersion) (ConfigurationVersion, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO platform.configuration_versions
			(fingerprint, openfga_model_id, schema_version, configuration)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (fingerprint) DO UPDATE SET
			openfga_model_id = EXCLUDED.openfga_model_id,
			schema_version = EXCLUDED.schema_version,
			configuration = EXCLUDED.configuration
		RETURNING id, fingerprint, openfga_model_id, schema_version, configuration,
			is_active, created_at, activated_at`,
		v.Fingerprint, v.OpenFGAModelID, v.SchemaVersion, jsonOrObject(v.Configuration))
	return scanConfiguration(row)
}

// ActivateConfiguration makes id the sole active model version atomically.
func (s *Store) ActivateConfiguration(ctx context.Context, id int64) error {
	return inTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE platform.configuration_versions
			SET is_active = false
			WHERE is_active AND id <> $1`, id); err != nil {
			return fmt.Errorf("deactivate configuration: %w", err)
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE platform.configuration_versions
			SET is_active = true, activated_at = now()
			WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("activate configuration: %w", err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (s *Store) ActiveConfiguration(ctx context.Context) (ConfigurationVersion, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, fingerprint, openfga_model_id, schema_version, configuration,
			is_active, created_at, activated_at
		FROM platform.configuration_versions WHERE is_active`)
	return scanConfiguration(row)
}

type rowScanner interface{ Scan(...any) error }

func scanConfiguration(row rowScanner) (ConfigurationVersion, error) {
	var v ConfigurationVersion
	err := row.Scan(&v.ID, &v.Fingerprint, &v.OpenFGAModelID, &v.SchemaVersion,
		&v.Configuration, &v.IsActive, &v.CreatedAt, &v.ActivatedAt)
	if err == sql.ErrNoRows {
		return v, ErrNotFound
	}
	if err != nil {
		return v, fmt.Errorf("scan configuration version: %w", err)
	}
	return v, nil
}
