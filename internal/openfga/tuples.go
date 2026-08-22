package openfga

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/pkg/storage"
)

type Tuple struct{ Object, Relation, User string }
type Check struct{ User, Relation, Object string }
type CheckResult struct {
	Allowed bool
	Err     error
}

func (e *Engine) WriteTuples(ctx context.Context, tuples []Tuple) error {
	return e.MutateTuples(ctx, nil, tuples)
}
func (e *Engine) DeleteTuples(ctx context.Context, tuples []Tuple) error {
	return e.MutateTuples(ctx, tuples, nil)
}

// MutateTuples applies deletes then writes in one OpenFGA datastore transaction.
// Repeated inserts and deletes are idempotent.
func (e *Engine) MutateTuples(ctx context.Context, deletes, writes []Tuple) error {
	if len(deletes)+len(writes) == 0 {
		return nil
	}
	a, err := e.Active(ctx)
	if err != nil {
		return fmt.Errorf("mutate OpenFGA tuples: %w", err)
	}
	req := &openfgav1.WriteRequest{StoreId: e.storeID, AuthorizationModelId: a.ModelID}
	if len(writes) > 0 {
		req.Writes = &openfgav1.WriteRequestWrites{OnDuplicate: "ignore"}
		for _, item := range writes {
			if err := validateTuple(item); err != nil {
				return err
			}
			req.Writes.TupleKeys = append(req.Writes.TupleKeys, &openfgav1.TupleKey{Object: item.Object, Relation: item.Relation, User: item.User})
		}
	}
	if len(deletes) > 0 {
		req.Deletes = &openfgav1.WriteRequestDeletes{OnMissing: "ignore"}
		for _, item := range deletes {
			if err := validateTuple(item); err != nil {
				return err
			}
			req.Deletes.TupleKeys = append(req.Deletes.TupleKeys, &openfgav1.TupleKeyWithoutCondition{Object: item.Object, Relation: item.Relation, User: item.User})
		}
	}
	if _, err := e.server.Write(ctx, req); err != nil {
		return fmt.Errorf("mutate OpenFGA tuples: %w", err)
	}
	return nil
}

func (e *Engine) BatchCheck(ctx context.Context, checks []Check) ([]CheckResult, error) {
	if len(checks) == 0 {
		return nil, nil
	}
	a, err := e.Active(ctx)
	if err != nil {
		return nil, fmt.Errorf("batch check OpenFGA: %w", err)
	}
	req := &openfgav1.BatchCheckRequest{StoreId: e.storeID, AuthorizationModelId: a.ModelID, Consistency: openfgav1.ConsistencyPreference_HIGHER_CONSISTENCY}
	for i, item := range checks {
		if item.User == "" || item.Relation == "" || item.Object == "" {
			return nil, fmt.Errorf("batch check OpenFGA: check %d has an empty field", i)
		}
		req.Checks = append(req.Checks, &openfgav1.BatchCheckItem{CorrelationId: strconv.Itoa(i), TupleKey: &openfgav1.CheckRequestTupleKey{User: item.User, Relation: item.Relation, Object: item.Object}})
	}
	resp, err := e.server.BatchCheck(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("batch check OpenFGA: %w", err)
	}
	out := make([]CheckResult, len(checks))
	for i := range checks {
		single, ok := resp.GetResult()[strconv.Itoa(i)]
		if !ok {
			out[i].Err = errors.New("OpenFGA omitted check result")
			continue
		}
		if checkErr := single.GetError(); checkErr != nil {
			out[i].Err = errors.New(checkErr.GetMessage())
		} else {
			out[i].Allowed = single.GetAllowed()
		}
	}
	return out, nil
}

// TuplesReferencingObject returns every tuple originating from object, directly
// targeting object as a user, or targeting one of object's usersets.
func (e *Engine) TuplesReferencingObject(ctx context.Context, object string) ([]Tuple, error) {
	if object == "" {
		return nil, errors.New("query OpenFGA tuples: object is required")
	}
	iter, err := e.ds.Read(ctx, e.storeID, storage.ReadFilter{}, storage.ReadOptions{Consistency: storage.ConsistencyOptions{Preference: openfgav1.ConsistencyPreference_HIGHER_CONSISTENCY}})
	if err != nil {
		return nil, fmt.Errorf("query OpenFGA tuples: %w", err)
	}
	defer iter.Stop()
	var out []Tuple
	for {
		record, err := iter.Next(ctx)
		if errors.Is(err, storage.ErrIteratorDone) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("query OpenFGA tuples: %w", err)
		}
		key := record.GetKey()
		if key.GetObject() == object || key.GetUser() == object || strings.HasPrefix(key.GetUser(), object+"#") {
			out = append(out, Tuple{Object: key.GetObject(), Relation: key.GetRelation(), User: key.GetUser()})
		}
	}
	return out, nil
}

// DeleteObjectTuples removes all associations that could survive deletion of a
// resource, including reverse userset references. It uses only public datastore
// reads and validated OpenFGA writes.
func (e *Engine) DeleteObjectTuples(ctx context.Context, object string) error {
	tuples, err := e.TuplesReferencingObject(ctx, object)
	if err != nil {
		return err
	}
	limit := e.ds.MaxTuplesPerWrite()
	for len(tuples) > 0 {
		n := limit
		if n > len(tuples) {
			n = len(tuples)
		}
		if err := e.DeleteTuples(ctx, tuples[:n]); err != nil {
			return err
		}
		tuples = tuples[n:]
	}
	return nil
}

func validateTuple(t Tuple) error {
	if t.Object == "" || t.Relation == "" || t.User == "" {
		return errors.New("mutate OpenFGA tuples: object, relation, and user are required")
	}
	return nil
}
