// Package api implements the public HTTP transport using only net/http. Domain
// services integrate through Backend and Authenticator adapters.
package api

import (
	"context"
	"encoding/json"
	"errors"
)

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string { return e.Message }

func Error(status int, code, message string) error {
	return &APIError{Status: status, Code: code, Message: message}
}

var ErrNotFound = errors.New("not found")
var ErrUnavailable = errors.New("storage or authorization engine unavailable")

type Identity struct {
	Subject     string
	Audience    string
	Permissions []string
	Context     any
}

type Authenticator interface {
	Authenticate(context.Context, string) (Identity, error)
}

// AuthenticationFailureAuditor is an optional backend capability. The API
// reports only categories and request IDs; bearer tokens are never exposed.
type AuthenticationFailureAuditor interface {
	AuditAuthenticationFailure(context.Context, string, string)
}

type OAuthMetadata struct {
	Issuer              string   `json:"issuer"`
	TokenEndpoint       string   `json:"token_endpoint"`
	JWKSURI             string   `json:"jwks_uri"`
	GrantTypesSupported []string `json:"grant_types_supported"`
	SubjectTypes        []string `json:"subject_types_supported"`
}

type TokenExchangeRequest struct {
	GrantType        string
	SubjectToken     string
	SubjectTokenType string
	ActorToken       string
	ActorTokenType   string
	Audience         string
}

type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

type ResourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}
type Subject struct {
	Type    string `json:"type"`
	Source  string `json:"source,omitempty"`
	Subject string `json:"subject,omitempty"`
	Group   string `json:"group,omitempty"`
}

type Audience struct {
	ID              string `json:"id"`
	DisplayName     string `json:"display_name,omitempty"`
	TokenTTLSeconds int64  `json:"token_ttl_seconds"`
	Delegation      struct {
		Enabled bool   `json:"enabled"`
		Mode    string `json:"mode"`
	} `json:"delegation"`
}
type AudiencePatch struct {
	DisplayName     *string `json:"display_name,omitempty"`
	TokenTTLSeconds *int64  `json:"token_ttl_seconds,omitempty"`
	Delegation      *struct {
		Enabled bool   `json:"enabled"`
		Mode    string `json:"mode"`
	} `json:"delegation,omitempty"`
}

type ResourceRelationships map[string][]ResourceRef

// UnmarshalJSON accepts the concise one-target form from the design as well
// as an array for many-cardinality relationships.
func (relationships *ResourceRelationships) UnmarshalJSON(data []byte) error {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	result := make(ResourceRelationships, len(values))
	for relation, raw := range values {
		var targets []ResourceRef
		if len(raw) > 0 && raw[0] == '[' {
			if err := json.Unmarshal(raw, &targets); err != nil {
				return err
			}
		} else {
			var target ResourceRef
			if err := json.Unmarshal(raw, &target); err != nil {
				return err
			}
			targets = []ResourceRef{target}
		}
		result[relation] = targets
	}
	*relationships = result
	return nil
}

type Resource struct {
	Type          string                `json:"type"`
	ID            string                `json:"id"`
	Metadata      map[string]any        `json:"metadata,omitempty"`
	Relationships ResourceRelationships `json:"relationships,omitempty"`
}
type ResourcePatch struct {
	Metadata map[string]any `json:"metadata,omitempty"`
}
type RelationshipMutation struct {
	Targets []ResourceRef `json:"targets,omitempty"`
	Target  *ResourceRef  `json:"target,omitempty"`
}

func (r RelationshipMutation) AllTargets() []ResourceRef {
	if r.Target != nil {
		return append(r.Targets, *r.Target)
	}
	return r.Targets
}

type Group struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
}
type MembershipRequest struct {
	Member Subject `json:"member"`
}
type Grant struct {
	ID                      string      `json:"id,omitempty"`
	Subject                 Subject     `json:"subject"`
	Role                    string      `json:"role"`
	Resource                ResourceRef `json:"resource"`
	CreateResourceIfMissing bool        `json:"create_resource_if_missing,omitempty"`
}

type CheckRequest struct {
	Checks []Check `json:"checks"`
}
type Check struct {
	ID         string      `json:"id"`
	Permission string      `json:"permission"`
	Resource   ResourceRef `json:"resource"`
}
type CheckResponse struct {
	Results []CheckResult `json:"results"`
}
type CheckResult struct {
	ID      string `json:"id"`
	Allowed bool   `json:"allowed"`
}

// Backend is intentionally transport-shaped. An adapter owns conversions to
// service/database/token domain types and their error taxonomy.
type Backend interface {
	OAuthMetadata(context.Context) (OAuthMetadata, error)
	JWKS(context.Context) (map[string]any, error)
	Exchange(context.Context, TokenExchangeRequest) (TokenExchangeResponse, error)
	Ready(context.Context) error

	CreateAudience(context.Context, Identity, Audience) (Audience, error)
	ListAudiences(context.Context, Identity) ([]Audience, error)
	GetAudience(context.Context, Identity, string) (Audience, error)
	PatchAudience(context.Context, Identity, string, AudiencePatch) (Audience, error)
	DeleteAudience(context.Context, Identity, string) error

	CreateResource(context.Context, Identity, Resource) (Resource, error)
	GetResource(context.Context, Identity, ResourceRef) (Resource, error)
	PatchResource(context.Context, Identity, ResourceRef, ResourcePatch) (Resource, error)
	DeleteResource(context.Context, Identity, ResourceRef) error
	PutRelationship(context.Context, Identity, ResourceRef, string, RelationshipMutation) error
	DeleteRelationship(context.Context, Identity, ResourceRef, string, RelationshipMutation) error

	CreateGroup(context.Context, Identity, Group) (Group, error)
	GetGroup(context.Context, Identity, string) (Group, error)
	DeleteGroup(context.Context, Identity, string) error
	AddMember(context.Context, Identity, string, MembershipRequest) error
	DeleteMember(context.Context, Identity, string, MembershipRequest) error

	CreateGrant(context.Context, Identity, Grant) (Grant, error)
	DeleteGrant(context.Context, Identity, string) error
	ListGrants(context.Context, Identity) ([]Grant, error)
	Check(context.Context, Identity, CheckRequest) (CheckResponse, error)
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}
type statusEnvelope struct {
	Status string `json:"status"`
}
