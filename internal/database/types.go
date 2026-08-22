// Package database contains the application-owned PostgreSQL persistence
// layer. OpenFGA data must be accessed through OpenFGA's supported interfaces,
// never through this package.
package database

import (
	"encoding/json"
	"errors"
	"time"
)

var ErrNotFound = errors.New("database: not found")
var ErrCardinality = errors.New("database: relationship cardinality violation")

type DelegationMode string

const (
	DelegationDisabled     DelegationMode = "disabled"
	DelegationSubject      DelegationMode = "subject"
	DelegationIntersection DelegationMode = "intersection"
	DelegationActor        DelegationMode = "actor"
	DelegationUnion        DelegationMode = "union"
)

type ConfigurationVersion struct {
	ID             int64
	Fingerprint    string
	OpenFGAModelID string
	SchemaVersion  string
	Configuration  json.RawMessage
	IsActive       bool
	CreatedAt      time.Time
	ActivatedAt    *time.Time
}

type Audience struct {
	ID              string
	DisplayName     string
	TokenTTLSeconds int
	DelegationMode  DelegationMode
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type ResourceRef struct {
	Type string
	ID   string
}

type Resource struct {
	ResourceRef
	Metadata  json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Cardinality string

const (
	CardinalityOne  Cardinality = "one"
	CardinalityMany Cardinality = "many"
)

type Relationship struct {
	Source      ResourceRef
	Relation    string
	Target      ResourceRef
	Cardinality Cardinality
	Tuple       AuthorizationTuple
	CreatedAt   time.Time
}

type Group struct {
	ID          string
	DisplayName string
	Metadata    json.RawMessage
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Subject struct {
	Kind      string // "principal" or "group"
	Source    string
	Principal string
	GroupID   string
}

func PrincipalSubject(source, subject string) Subject {
	return Subject{Kind: "principal", Source: source, Principal: subject}
}

func GroupSubject(id string) Subject { return Subject{Kind: "group", GroupID: id} }

type Membership struct {
	ID        int64
	GroupID   string
	Member    Subject
	Tuple     AuthorizationTuple
	CreatedAt time.Time
}

type Grant struct {
	ID        string
	Subject   Subject
	Role      string
	Resource  ResourceRef
	Tuple     AuthorizationTuple
	CreatedAt time.Time
}

type GrantFilter struct {
	Subject       *Subject
	Resource      *ResourceRef
	Role          string
	Limit, Offset int
}

type TupleOperation struct {
	OperationID string
	Action      string // "write" or "delete"
	Object      string
	Relation    string
	Subject     string
	State       string
	Attempts    int
	LastError   *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CompletedAt *time.Time
}

// AuthorizationTuple is the exact OpenFGA representation compiled by the
// service layer. Persisting it makes tuple cleanup independent of later schema
// or identifier-encoding changes.
type AuthorizationTuple struct {
	Object   string
	Relation string
	Subject  string
}

type AuditEvent struct {
	ID             int64
	OccurredAt     time.Time
	RequestID      *string
	ActorPrincipal *string
	Operation      string
	Target         string
	Result         string
	PreviousValue  json.RawMessage
	NewValue       json.RawMessage
	Details        json.RawMessage
}

type AuditFilter struct {
	RequestID string
	Operation string
	Limit     int
}
