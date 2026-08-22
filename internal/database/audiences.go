package database

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *Store) PutAudience(ctx context.Context, a Audience) (Audience, error) {
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO platform.resources (resource_type, resource_id)
			VALUES ('audience', $1) ON CONFLICT DO NOTHING`, a.ID); err != nil {
			return fmt.Errorf("ensure audience resource: %w", err)
		}
		row := tx.QueryRowContext(ctx, `
			INSERT INTO platform.audiences
				(id, display_name, token_ttl_seconds, delegation_mode)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (id) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				token_ttl_seconds = EXCLUDED.token_ttl_seconds,
				delegation_mode = EXCLUDED.delegation_mode,
				updated_at = now()
			RETURNING id, display_name, token_ttl_seconds, delegation_mode, created_at, updated_at`,
			a.ID, a.DisplayName, a.TokenTTLSeconds, a.DelegationMode)
		var err error
		a, err = scanAudience(row)
		return err
	})
	return a, err
}

func (s *Store) Audience(ctx context.Context, id string) (Audience, error) {
	return scanAudience(s.db.QueryRowContext(ctx, `
		SELECT id, display_name, token_ttl_seconds, delegation_mode, created_at, updated_at
		FROM platform.audiences WHERE id = $1`, id))
}

func (s *Store) Audiences(ctx context.Context, limit, offset int) ([]Audience, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, display_name, token_ttl_seconds, delegation_mode, created_at, updated_at
		FROM platform.audiences ORDER BY id LIMIT $1 OFFSET $2`, limitOrDefault(limit), max(offset, 0))
	if err != nil {
		return nil, fmt.Errorf("list audiences: %w", err)
	}
	defer rows.Close()
	var out []Audience
	for rows.Next() {
		a, err := scanAudience(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAudience also removes the intrinsic audience resource. Cascading
// resource constraints remove associated relationships and grants.
func (s *Store) DeleteAudience(ctx context.Context, id string) (bool, error) {
	var deleted bool
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM platform.audiences WHERE id = $1`, id); err != nil {
			return fmt.Errorf("delete audience: %w", err)
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM platform.resources WHERE resource_type = 'audience' AND resource_id = $1`, id)
		if err != nil {
			return fmt.Errorf("delete audience resource: %w", err)
		}
		n, err := result.RowsAffected()
		deleted = n > 0
		return err
	})
	return deleted, err
}

func scanAudience(row rowScanner) (Audience, error) {
	var a Audience
	err := row.Scan(&a.ID, &a.DisplayName, &a.TokenTTLSeconds, &a.DelegationMode, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return a, ErrNotFound
	}
	if err != nil {
		return a, fmt.Errorf("scan audience: %w", err)
	}
	return a, nil
}
