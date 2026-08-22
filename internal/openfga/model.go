package openfga

import (
	"context"
	"errors"
	"fmt"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/pkg/typesystem"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/authorization/compiler"
)

func (e *Engine) ActivateModel(ctx context.Context, fingerprint string, model *compiler.Model) (Activation, error) {
	if fingerprint == "" {
		return Activation{}, errors.New("activate OpenFGA model: fingerprint is required")
	}
	protoModel, err := ToProto(model)
	if err != nil {
		return Activation{}, err
	}
	if _, err := typesystem.NewAndValidate(ctx, protoModel); err != nil {
		return Activation{}, fmt.Errorf("validate OpenFGA model: %w", err)
	}
	resp, err := e.server.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{StoreId: e.storeID, SchemaVersion: protoModel.GetSchemaVersion(), TypeDefinitions: protoModel.GetTypeDefinitions(), Conditions: protoModel.GetConditions()})
	if err != nil {
		return Activation{}, fmt.Errorf("write OpenFGA authorization model: %w", err)
	}
	a := Activation{StoreID: e.storeID, Fingerprint: fingerprint, ModelID: resp.GetAuthorizationModelId(), SchemaVersion: 1, ActivatedAt: time.Now().UTC()}
	if err := e.activations.SaveActive(ctx, a); err != nil {
		return Activation{}, fmt.Errorf("record OpenFGA model activation: %w", err)
	}
	return a, nil
}

func (e *Engine) Active(ctx context.Context) (Activation, error) {
	return e.activations.LoadActive(ctx, e.storeID)
}

func (e *Engine) VerifyFingerprint(ctx context.Context, fingerprint string) (Activation, error) {
	a, err := e.Active(ctx)
	if err != nil {
		return Activation{}, err
	}
	if a.Fingerprint != fingerprint {
		return Activation{}, fmt.Errorf("%w: active=%s configured=%s", ErrFingerprintMismatch, a.Fingerprint, fingerprint)
	}
	if _, err := e.ds.ReadAuthorizationModel(ctx, e.storeID, a.ModelID); err != nil {
		return Activation{}, fmt.Errorf("read active OpenFGA model %s: %w", a.ModelID, err)
	}
	return a, nil
}

func (e *Engine) EnsureModel(ctx context.Context, fingerprint string, model *compiler.Model) (Activation, bool, error) {
	a, err := e.VerifyFingerprint(ctx, fingerprint)
	if err == nil {
		return a, false, nil
	}
	if !errors.Is(err, ErrNoActivation) && !errors.Is(err, ErrFingerprintMismatch) {
		return Activation{}, false, err
	}
	a, err = e.ActivateModel(ctx, fingerprint, model)
	return a, true, err
}

func ToProto(model *compiler.Model) (*openfgav1.AuthorizationModel, error) {
	if model == nil {
		return nil, errors.New("convert OpenFGA model: nil compiler model")
	}
	if err := model.Validate(); err != nil {
		return nil, fmt.Errorf("convert OpenFGA model: %w", err)
	}
	out := &openfgav1.AuthorizationModel{SchemaVersion: model.SchemaVersion}
	for _, td := range model.TypeDefinitions {
		converted := &openfgav1.TypeDefinition{Type: td.Type, Relations: map[string]*openfgav1.Userset{}}
		for name, rewrite := range td.Relations {
			u, err := usersetToProto(rewrite)
			if err != nil {
				return nil, fmt.Errorf("convert %s#%s: %w", td.Type, name, err)
			}
			converted.Relations[name] = u
		}
		if td.Metadata != nil {
			converted.Metadata = &openfgav1.Metadata{Relations: map[string]*openfgav1.RelationMetadata{}}
			for name, metadata := range td.Metadata.Relations {
				rm := &openfgav1.RelationMetadata{}
				for _, ref := range metadata.DirectlyRelatedUserTypes {
					rr := &openfgav1.RelationReference{Type: ref.Type}
					if ref.Relation != nil {
						rr.RelationOrWildcard = &openfgav1.RelationReference_Relation{Relation: *ref.Relation}
					}
					rm.DirectlyRelatedUserTypes = append(rm.DirectlyRelatedUserTypes, rr)
				}
				converted.Metadata.Relations[name] = rm
			}
		}
		out.TypeDefinitions = append(out.TypeDefinitions, converted)
	}
	return out, nil
}

func usersetToProto(in compiler.Userset) (*openfgav1.Userset, error) {
	n := 0
	var out *openfgav1.Userset
	if in.This != nil {
		n++
		out = &openfgav1.Userset{Userset: &openfgav1.Userset_This{This: &openfgav1.DirectUserset{}}}
	}
	if in.ComputedUserset != nil {
		n++
		out = &openfgav1.Userset{Userset: &openfgav1.Userset_ComputedUserset{ComputedUserset: &openfgav1.ObjectRelation{Relation: in.ComputedUserset.Relation}}}
	}
	if in.TupleToUserset != nil {
		n++
		out = &openfgav1.Userset{Userset: &openfgav1.Userset_TupleToUserset{TupleToUserset: &openfgav1.TupleToUserset{Tupleset: &openfgav1.ObjectRelation{Relation: in.TupleToUserset.Tupleset.Relation}, ComputedUserset: &openfgav1.ObjectRelation{Relation: in.TupleToUserset.ComputedUserset.Relation}}}}
	}
	if in.Union != nil {
		n++
		children := make([]*openfgav1.Userset, 0, len(in.Union.Child))
		for _, child := range in.Union.Child {
			u, err := usersetToProto(child)
			if err != nil {
				return nil, err
			}
			children = append(children, u)
		}
		out = &openfgav1.Userset{Userset: &openfgav1.Userset_Union{Union: &openfgav1.Usersets{Child: children}}}
	}
	if n != 1 {
		return nil, fmt.Errorf("userset must contain exactly one rewrite, got %d", n)
	}
	return out, nil
}
