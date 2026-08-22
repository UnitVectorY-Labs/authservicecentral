// Package service implements runtime authorization policy and coordinates the
// application catalog with an OpenFGA-compatible engine.
package service

import (
	"context"
	"encoding/json"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

// Engine is the deliberately small surface required from the embedded OpenFGA
// adapter. Tuple writes and deletes must be idempotent.
type Engine interface {
	WriteTuple(context.Context, database.AuthorizationTuple) error
	DeleteTuple(context.Context, database.AuthorizationTuple) error
	BatchCheck(context.Context, []EngineCheck) ([]bool, error)
}

type EngineCheck struct {
	Subject  string
	Relation string
	Object   string
}

type Mutation struct {
	RequestID   string
	Actor       string
	OperationID string
}

type CreateResourceRequest struct {
	Resource      database.Resource
	Relationships map[string][]database.ResourceRef
}

type RelationshipRequest struct {
	Source   database.ResourceRef
	Relation string
	Targets  []database.ResourceRef
}

type CreateGrantRequest struct {
	Grant                   database.Grant
	CreateResourceIfMissing bool
	ResourceMetadata        json.RawMessage
}

type PermissionCheck struct {
	Permission string
	Resource   database.ResourceRef
}

type BatchCheckRequest struct {
	Subject database.Subject
	Actor   *database.Subject
	Mode    database.DelegationMode
	Checks  []PermissionCheck
}

type CheckResult struct {
	Permission string
	Resource   database.ResourceRef
	Allowed    bool
}
