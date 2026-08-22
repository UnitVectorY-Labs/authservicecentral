package database

import (
	"context"
	"fmt"
)

func (s *Store) AppendAuditEvent(ctx context.Context, e AuditEvent) (AuditEvent, error) {
	row := s.db.QueryRowContext(ctx, `INSERT INTO platform.audit_events
		(request_id,actor_principal,operation,target,result,previous_value,new_value,details)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,occurred_at`,
		e.RequestID, e.ActorPrincipal, e.Operation, e.Target, e.Result, nullJSON(e.PreviousValue), nullJSON(e.NewValue), jsonOrObject(e.Details))
	if err := row.Scan(&e.ID, &e.OccurredAt); err != nil {
		return e, fmt.Errorf("append audit event: %w", err)
	}
	return e, nil
}

func (s *Store) AuditEvents(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,occurred_at,request_id,actor_principal,operation,target,
		result,previous_value,new_value,details FROM platform.audit_events
		WHERE ($1='' OR request_id=$1) AND ($2='' OR operation=$2)
		ORDER BY occurred_at DESC,id DESC LIMIT $3`, f.RequestID, f.Operation, limitOrDefault(f.Limit))
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var previous, next []byte
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.RequestID, &e.ActorPrincipal, &e.Operation, &e.Target,
			&e.Result, &previous, &next, &e.Details); err != nil {
			return nil, err
		}
		e.PreviousValue, e.NewValue = previous, next
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullJSON(v []byte) any {
	if len(v) == 0 {
		return nil
	}
	return v
}
