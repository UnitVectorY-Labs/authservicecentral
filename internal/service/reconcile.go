package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

// Reconcile claims pending/failed tuple operations and applies them through
// the supported engine interface. Failures remain retryable in the outbox.
func (s *Service) Reconcile(ctx context.Context, mutation Mutation, limit int) (int, error) {
	if err := validateMutation(mutation); err != nil {
		return 0, err
	}
	operations, err := s.db.ClaimTupleOperations(ctx, limit)
	if err != nil {
		return 0, err
	}
	var errs []error
	completed := 0
	for _, operation := range operations {
		tuple := database.AuthorizationTuple{Object: operation.Object, Relation: operation.Relation, Subject: operation.Subject}
		var applyErr error
		switch operation.Action {
		case "write":
			applyErr = s.engine.WriteTuple(ctx, tuple)
		case "delete":
			applyErr = s.engine.DeleteTuple(ctx, tuple)
		default:
			applyErr = fmt.Errorf("unsupported tuple action %q", operation.Action)
		}
		if applyErr != nil {
			if stateErr := s.db.FailTupleOperation(ctx, operation.OperationID, applyErr.Error()); stateErr != nil {
				errs = append(errs, stateErr)
			}
			_ = s.audit(ctx, mutation, "authorization.tuple.reconciled", operation.OperationID, "failure", operation, map[string]string{"error": applyErr.Error()})
			errs = append(errs, fmt.Errorf("operation %s: %w", operation.OperationID, applyErr))
			continue
		}
		if err := s.db.CompleteTupleOperation(ctx, operation.OperationID); err != nil {
			errs = append(errs, err)
			continue
		}
		completed++
		if err := s.audit(ctx, mutation, "authorization.tuple.reconciled", operation.OperationID, "success", operation, tuple); err != nil {
			errs = append(errs, err)
		}
	}
	return completed, errors.Join(errs...)
}
