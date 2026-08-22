package app

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
	engine "github.com/UnitVectorY-Labs/authservicecentral/internal/openfga"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/service"
)

// ActivationStore persists the application-owned pointer to OpenFGA's
// immutable active model. OpenFGA's private tables remain untouched.
type ActivationStore struct{ DB *database.Store }

func (a ActivationStore) LoadActive(ctx context.Context, storeID string) (engine.Activation, error) {
	v, err := a.DB.ActiveConfiguration(ctx)
	if errors.Is(err, database.ErrNotFound) {
		return engine.Activation{}, engine.ErrNoActivation
	}
	if err != nil {
		return engine.Activation{}, err
	}
	schemaVersion, _ := strconv.Atoi(v.SchemaVersion)
	return engine.Activation{StoreID: storeID, Fingerprint: v.Fingerprint, ModelID: v.OpenFGAModelID, SchemaVersion: schemaVersion, ActivatedAt: valueTime(v.ActivatedAt, v.CreatedAt)}, nil
}

func (a ActivationStore) SaveActive(ctx context.Context, active engine.Activation) error {
	configuration, _ := json.Marshal(map[string]string{"openfga_store_id": active.StoreID})
	v, err := a.DB.PutConfigurationVersion(ctx, database.ConfigurationVersion{Fingerprint: active.Fingerprint, OpenFGAModelID: active.ModelID, SchemaVersion: strconv.Itoa(active.SchemaVersion), Configuration: configuration})
	if err != nil {
		return err
	}
	return a.DB.ActivateConfiguration(ctx, v.ID)
}

// ServiceEngine adapts the official embedded engine to the deliberately small
// domain-service interface.
type ServiceEngine struct{ Engine *engine.Engine }

func (a ServiceEngine) WriteTuple(ctx context.Context, tuple database.AuthorizationTuple) error {
	return a.Engine.WriteTuples(ctx, []engine.Tuple{{Object: tuple.Object, Relation: tuple.Relation, User: tuple.Subject}})
}
func (a ServiceEngine) DeleteTuple(ctx context.Context, tuple database.AuthorizationTuple) error {
	return a.Engine.DeleteTuples(ctx, []engine.Tuple{{Object: tuple.Object, Relation: tuple.Relation, User: tuple.Subject}})
}
func (a ServiceEngine) BatchCheck(ctx context.Context, checks []service.EngineCheck) ([]bool, error) {
	in := make([]engine.Check, len(checks))
	for i, c := range checks {
		in[i] = engine.Check{User: c.Subject, Relation: c.Relation, Object: c.Object}
	}
	results, err := a.Engine.BatchCheck(ctx, in)
	if err != nil {
		return nil, err
	}
	out := make([]bool, len(results))
	for i, result := range results {
		if result.Err != nil {
			return nil, result.Err
		}
		out[i] = result.Allowed
	}
	return out, nil
}
