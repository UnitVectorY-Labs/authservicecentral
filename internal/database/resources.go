package database

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *Store) CreateResource(ctx context.Context, r Resource) (Resource, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO platform.resources (resource_type, resource_id, metadata)
		VALUES ($1, $2, $3)
		RETURNING resource_type, resource_id, metadata, created_at, updated_at`,
		r.Type, r.ID, jsonOrObject(r.Metadata))
	return scanResource(row)
}

func (s *Store) Resource(ctx context.Context, ref ResourceRef) (Resource, error) {
	return scanResource(s.db.QueryRowContext(ctx, `
		SELECT resource_type, resource_id, metadata, created_at, updated_at
		FROM platform.resources WHERE resource_type = $1 AND resource_id = $2`, ref.Type, ref.ID))
}

func (s *Store) UpdateResource(ctx context.Context, r Resource) (Resource, error) {
	return scanResource(s.db.QueryRowContext(ctx, `
		UPDATE platform.resources SET metadata=$3, updated_at=now()
		WHERE resource_type=$1 AND resource_id=$2
		RETURNING resource_type, resource_id, metadata, created_at, updated_at`,
		r.Type, r.ID, jsonOrObject(r.Metadata)))
}

func (s *Store) Resources(ctx context.Context, resourceType string, limit, offset int) ([]Resource, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT resource_type, resource_id, metadata, created_at, updated_at
		FROM platform.resources
		WHERE ($1 = '' OR resource_type = $1)
		ORDER BY resource_type, resource_id LIMIT $2 OFFSET $3`,
		resourceType, limitOrDefault(limit), max(offset, 0))
	if err != nil {
		return nil, fmt.Errorf("list resources: %w", err)
	}
	defer rows.Close()
	var out []Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteResource atomically queues deletion of all exact OpenFGA tuples which
// refer to ref, then removes the catalog record. operationPrefix must be a
// stable request/operation ID so retries produce the same outbox keys.
func (s *Store) DeleteResource(ctx context.Context, ref ResourceRef, operationPrefix string) (bool, error) {
	var deleted bool
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT tuple_object, tuple_relation, tuple_subject FROM platform.resource_relationships
			WHERE (source_type = $1 AND source_id = $2) OR (target_type = $1 AND target_id = $2)
			UNION
			SELECT tuple_object, tuple_relation, tuple_subject FROM platform.grants
			WHERE resource_type = $1 AND resource_id = $2`, ref.Type, ref.ID)
		if err != nil {
			return fmt.Errorf("select resource tuples: %w", err)
		}
		var tuples []AuthorizationTuple
		for rows.Next() {
			var tuple AuthorizationTuple
			if err := rows.Scan(&tuple.Object, &tuple.Relation, &tuple.Subject); err != nil {
				rows.Close()
				return err
			}
			tuples = append(tuples, tuple)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for i, tuple := range tuples {
			op := TupleOperation{OperationID: fmt.Sprintf("%s:delete:%d", operationPrefix, i), Action: "delete", Object: tuple.Object, Relation: tuple.Relation, Subject: tuple.Subject}
			if err := enqueueTuple(ctx, tx, op); err != nil {
				return err
			}
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM platform.resources WHERE resource_type = $1 AND resource_id = $2`, ref.Type, ref.ID)
		if err != nil {
			return fmt.Errorf("delete resource: %w", err)
		}
		n, err := result.RowsAffected()
		deleted = n > 0
		return err
	})
	return deleted, err
}

func (s *Store) PutRelationship(ctx context.Context, r Relationship, op TupleOperation) error {
	return inTx(ctx, s.db, func(tx *sql.Tx) error {
		// Lock the source catalog row so concurrent changes to the same logical
		// relationship cannot both pass the cardinality check.
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM platform.resources
			WHERE resource_type=$1 AND resource_id=$2 FOR UPDATE`, r.Source.Type, r.Source.ID).Scan(&exists); err != nil {
			if err == sql.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		var conflicting bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM platform.resource_relationships
			WHERE source_type=$1 AND source_id=$2 AND relation=$3
			AND (target_type<>$4 OR target_id<>$5)
			AND (cardinality='one' OR $6='one'))`, r.Source.Type, r.Source.ID, r.Relation,
			r.Target.Type, r.Target.ID, r.Cardinality).Scan(&conflicting); err != nil {
			return err
		}
		if conflicting {
			return ErrCardinality
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO platform.resource_relationships
				(source_type, source_id, relation, target_type, target_id, cardinality,
				 tuple_object, tuple_relation, tuple_subject)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (source_type, source_id, relation, target_type, target_id)
			DO UPDATE SET cardinality = EXCLUDED.cardinality,
				tuple_object = EXCLUDED.tuple_object, tuple_relation = EXCLUDED.tuple_relation,
				tuple_subject = EXCLUDED.tuple_subject`,
			r.Source.Type, r.Source.ID, r.Relation, r.Target.Type, r.Target.ID, r.Cardinality,
			r.Tuple.Object, r.Tuple.Relation, r.Tuple.Subject)
		if err != nil {
			return fmt.Errorf("put relationship: %w", err)
		}
		op.Action = "write"
		op.Object = r.Tuple.Object
		op.Relation = r.Tuple.Relation
		op.Subject = r.Tuple.Subject
		return enqueueTuple(ctx, tx, op)
	})
}

func (s *Store) DeleteRelationship(ctx context.Context, source ResourceRef, relation string, target ResourceRef, op TupleOperation) (bool, error) {
	var deleted bool
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM platform.resource_relationships
			WHERE source_type=$1 AND source_id=$2 AND relation=$3 AND target_type=$4 AND target_id=$5`,
			source.Type, source.ID, relation, target.Type, target.ID)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		deleted = n > 0
		if err != nil || !deleted {
			return err
		}
		return enqueueTuple(ctx, tx, op)
	})
	return deleted, err
}

func (s *Store) Relationships(ctx context.Context, source ResourceRef) ([]Relationship, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source_type, source_id, relation, target_type, target_id,
		cardinality, tuple_object, tuple_relation, tuple_subject, created_at
		FROM platform.resource_relationships WHERE source_type=$1 AND source_id=$2
		ORDER BY relation, target_type, target_id`, source.Type, source.ID)
	if err != nil {
		return nil, fmt.Errorf("list relationships: %w", err)
	}
	defer rows.Close()
	var out []Relationship
	for rows.Next() {
		var r Relationship
		if err := rows.Scan(&r.Source.Type, &r.Source.ID, &r.Relation, &r.Target.Type, &r.Target.ID,
			&r.Cardinality, &r.Tuple.Object, &r.Tuple.Relation, &r.Tuple.Subject, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanResource(row rowScanner) (Resource, error) {
	var r Resource
	err := row.Scan(&r.Type, &r.ID, &r.Metadata, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return r, ErrNotFound
	}
	if err != nil {
		return r, fmt.Errorf("scan resource: %w", err)
	}
	return r, nil
}
