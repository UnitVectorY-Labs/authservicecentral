package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func (s *Store) EnqueueTuple(ctx context.Context, op TupleOperation) error {
	return enqueueTuple(ctx, s.db, op)
}

func enqueueTuple(ctx context.Context, q dbtx, op TupleOperation) error {
	if op.OperationID == "" || op.Object == "" || op.Relation == "" || op.Subject == "" || (op.Action != "write" && op.Action != "delete") {
		return errors.New("database: invalid authorization operation")
	}
	result, err := q.ExecContext(ctx, `INSERT INTO platform.authorization_operations
		(operation_id, action, object, relation, subject)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (operation_id) DO UPDATE SET operation_id=EXCLUDED.operation_id
		WHERE platform.authorization_operations.action=EXCLUDED.action
		  AND platform.authorization_operations.object=EXCLUDED.object
		  AND platform.authorization_operations.relation=EXCLUDED.relation
		  AND platform.authorization_operations.subject=EXCLUDED.subject`,
		op.OperationID, op.Action, op.Object, op.Relation, op.Subject)
	if err != nil {
		return fmt.Errorf("enqueue authorization operation: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("database: operation ID reused for a different tuple")
	}
	return nil
}

// ClaimTupleOperations atomically claims retryable work. Multiple workers can
// call it concurrently; SKIP LOCKED ensures an operation has one owner.
func (s *Store) ClaimTupleOperations(ctx context.Context, limit int) ([]TupleOperation, error) {
	rows, err := s.db.QueryContext(ctx, `WITH selected AS (
		SELECT operation_id FROM platform.authorization_operations
		WHERE state IN ('pending','failed')
		   OR (state='processing' AND updated_at < now() - interval '1 minute')
		ORDER BY created_at
		FOR UPDATE SKIP LOCKED LIMIT $1
	) UPDATE platform.authorization_operations o
	SET state='processing', attempts=o.attempts+1, updated_at=now(), last_error=NULL
	FROM selected WHERE o.operation_id=selected.operation_id
	RETURNING o.operation_id,o.action,o.object,o.relation,o.subject,o.state,o.attempts,
		o.last_error,o.created_at,o.updated_at,o.completed_at`, limitOrDefault(limit))
	if err != nil {
		return nil, fmt.Errorf("claim authorization operations: %w", err)
	}
	defer rows.Close()
	var out []TupleOperation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

func (s *Store) CompleteTupleOperation(ctx context.Context, id string) error {
	return transitionOperation(ctx, s.db, id, "completed", nil)
}

func (s *Store) FailTupleOperation(ctx context.Context, id, message string) error {
	return transitionOperation(ctx, s.db, id, "failed", &message)
}

func transitionOperation(ctx context.Context, q dbtx, id, state string, message *string) error {
	result, err := q.ExecContext(ctx, `UPDATE platform.authorization_operations
		SET state=$2,last_error=$3,updated_at=now(),completed_at=CASE WHEN $2='completed' THEN now() ELSE NULL END
		WHERE operation_id=$1`, id, state, message)
	if err != nil {
		return fmt.Errorf("transition authorization operation: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanOperation(row rowScanner) (TupleOperation, error) {
	var op TupleOperation
	err := row.Scan(&op.OperationID, &op.Action, &op.Object, &op.Relation, &op.Subject, &op.State,
		&op.Attempts, &op.LastError, &op.CreatedAt, &op.UpdatedAt, &op.CompletedAt)
	if err == sql.ErrNoRows {
		return op, ErrNotFound
	}
	return op, err
}
