package database

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *Store) CreateGroup(ctx context.Context, g Group) (Group, error) {
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO platform.resources (resource_type, resource_id, metadata)
			VALUES ('group',$1,$2)`, g.ID, jsonOrObject(g.Metadata)); err != nil {
			return fmt.Errorf("create group resource: %w", err)
		}
		row := tx.QueryRowContext(ctx, `INSERT INTO platform.groups (id, display_name, metadata)
			VALUES ($1,$2,$3) RETURNING id, display_name, metadata, created_at, updated_at`,
			g.ID, g.DisplayName, jsonOrObject(g.Metadata))
		var err error
		g, err = scanGroup(row)
		return err
	})
	return g, err
}

func (s *Store) Group(ctx context.Context, id string) (Group, error) {
	return scanGroup(s.db.QueryRowContext(ctx, `SELECT id, display_name, metadata, created_at, updated_at
		FROM platform.groups WHERE id=$1`, id))
}

func (s *Store) DeleteGroup(ctx context.Context, id, operationPrefix string) (bool, error) {
	var deleted bool
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT tuple_object, tuple_relation, tuple_subject FROM platform.group_memberships
			WHERE group_id=$1 OR member_group_id=$1
			UNION SELECT tuple_object, tuple_relation, tuple_subject FROM platform.grants WHERE subject_group_id=$1
			UNION SELECT tuple_object, tuple_relation, tuple_subject FROM platform.grants
			WHERE resource_type='group' AND resource_id=$1
			UNION SELECT tuple_object, tuple_relation, tuple_subject FROM platform.resource_relationships
			WHERE (source_type='group' AND source_id=$1) OR (target_type='group' AND target_id=$1)`, id)
		if err != nil {
			return fmt.Errorf("select group tuples: %w", err)
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
			if err := enqueueTuple(ctx, tx, TupleOperation{OperationID: fmt.Sprintf("%s:delete:%d", operationPrefix, i), Action: "delete", Object: tuple.Object, Relation: tuple.Relation, Subject: tuple.Subject}); err != nil {
				return err
			}
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM platform.groups WHERE id=$1`, id)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		deleted = n > 0
		if _, err := tx.ExecContext(ctx, `DELETE FROM platform.resources WHERE resource_type='group' AND resource_id=$1`, id); err != nil {
			return err
		}
		return nil
	})
	return deleted, err
}

func (s *Store) AddMembership(ctx context.Context, m Membership, op TupleOperation) (Membership, error) {
	var source, principal, memberGroup any
	if m.Member.Kind == "principal" {
		source, principal = m.Member.Source, m.Member.Principal
	} else {
		memberGroup = m.Member.GroupID
	}
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `INSERT INTO platform.group_memberships
			(group_id, member_kind, principal_source, principal_subject, member_group_id,
			 tuple_object, tuple_relation, tuple_subject)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			RETURNING id, created_at`, m.GroupID, m.Member.Kind, source, principal, memberGroup,
			m.Tuple.Object, m.Tuple.Relation, m.Tuple.Subject)
		if err := row.Scan(&m.ID, &m.CreatedAt); err != nil {
			return fmt.Errorf("add membership: %w", err)
		}
		op.Action = "write"
		op.Object = m.Tuple.Object
		op.Relation = m.Tuple.Relation
		op.Subject = m.Tuple.Subject
		return enqueueTuple(ctx, tx, op)
	})
	return m, err
}

func (s *Store) DeleteMembership(ctx context.Context, id int64, operationID string) (bool, error) {
	var deleted bool
	err := inTx(ctx, s.db, func(tx *sql.Tx) error {
		var tuple AuthorizationTuple
		err := tx.QueryRowContext(ctx, `DELETE FROM platform.group_memberships WHERE id=$1
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

func (s *Store) Memberships(ctx context.Context, groupID string) ([]Membership, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, group_id, member_kind, principal_source,
		principal_subject, member_group_id, tuple_object, tuple_relation, tuple_subject, created_at
		FROM platform.group_memberships WHERE group_id=$1 ORDER BY id`, groupID)
	if err != nil {
		return nil, fmt.Errorf("list memberships: %w", err)
	}
	defer rows.Close()
	var out []Membership
	for rows.Next() {
		var m Membership
		var source, principal, memberGroup sql.NullString
		if err := rows.Scan(&m.ID, &m.GroupID, &m.Member.Kind, &source, &principal, &memberGroup,
			&m.Tuple.Object, &m.Tuple.Relation, &m.Tuple.Subject, &m.CreatedAt); err != nil {
			return nil, err
		}
		m.Member.Source, m.Member.Principal, m.Member.GroupID = source.String, principal.String, memberGroup.String
		out = append(out, m)
	}
	return out, rows.Err()
}

func scanGroup(row rowScanner) (Group, error) {
	var g Group
	err := row.Scan(&g.ID, &g.DisplayName, &g.Metadata, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return g, ErrNotFound
	}
	if err != nil {
		return g, fmt.Errorf("scan group: %w", err)
	}
	return g, nil
}
