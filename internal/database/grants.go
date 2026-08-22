package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func (s *Store) CreateGrant(ctx context.Context, g Grant, op TupleOperation) (Grant, error) {
	var source, principal, group any
	if g.Subject.Kind == "principal" {
		source, principal = g.Subject.Source, g.Subject.Principal
	} else {
		group = g.Subject.GroupID
	}
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `INSERT INTO platform.grants
			(id, subject_kind, principal_source, principal_subject, subject_group_id, role,
			 resource_type, resource_id, tuple_object, tuple_relation, tuple_subject)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING created_at`,
			g.ID, g.Subject.Kind, source, principal, group, g.Role, g.Resource.Type, g.Resource.ID,
			g.Tuple.Object, g.Tuple.Relation, g.Tuple.Subject)
		if err := row.Scan(&g.CreatedAt); err != nil {
			return fmt.Errorf("create grant: %w", err)
		}
		op.Action = "write"
		op.Object = g.Tuple.Object
		op.Relation = g.Tuple.Relation
		op.Subject = g.Tuple.Subject
		return enqueueTuple(ctx, tx, op)
	})
	return g, err
}

func (s *Store) DeleteGrant(ctx context.Context, id, operationID string) (bool, error) {
	var deleted bool
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		var tuple AuthorizationTuple
		err := tx.QueryRowContext(ctx, `DELETE FROM platform.grants WHERE id=$1
			RETURNING tuple_object, tuple_relation, tuple_subject`, id).Scan(&tuple.Object, &tuple.Relation, &tuple.Subject)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		deleted = true
		return enqueueTuple(ctx, tx, TupleOperation{OperationID: operationID, Action: "delete", Object: tuple.Object, Relation: tuple.Relation, Subject: tuple.Subject})
	})
	return deleted, err
}

func (s *Store) Grants(ctx context.Context, f GrantFilter) ([]Grant, error) {
	var where []string
	var args []any
	arg := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }
	if f.Role != "" {
		where = append(where, "role="+arg(f.Role))
	}
	if f.Resource != nil {
		where = append(where, "resource_type="+arg(f.Resource.Type), "resource_id="+arg(f.Resource.ID))
	}
	if f.Subject != nil {
		where = append(where, "subject_kind="+arg(f.Subject.Kind))
		if f.Subject.Kind == "group" {
			where = append(where, "subject_group_id="+arg(f.Subject.GroupID))
		} else {
			where = append(where, "principal_source="+arg(f.Subject.Source), "principal_subject="+arg(f.Subject.Principal))
		}
	}
	query := `SELECT id, subject_kind, principal_source, principal_subject, subject_group_id,
		role, resource_type, resource_id, tuple_object, tuple_relation, tuple_subject, created_at FROM platform.grants`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at, id LIMIT " + arg(limitOrDefault(f.Limit)) + " OFFSET " + arg(max(f.Offset, 0))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		var source, principal, group sql.NullString
		if err := rows.Scan(&g.ID, &g.Subject.Kind, &source, &principal, &group, &g.Role,
			&g.Resource.Type, &g.Resource.ID, &g.Tuple.Object, &g.Tuple.Relation, &g.Tuple.Subject, &g.CreatedAt); err != nil {
			return nil, err
		}
		g.Subject.Source, g.Subject.Principal, g.Subject.GroupID = source.String, principal.String, group.String
		out = append(out, g)
	}
	return out, rows.Err()
}
