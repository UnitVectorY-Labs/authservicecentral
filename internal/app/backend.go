package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/api"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/authn"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
	engine "github.com/UnitVectorY-Labs/authservicecentral/internal/openfga"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/service"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/signing"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/token"
)

type PlatformAuthenticator struct{ Parser *token.Parser }

func (a PlatformAuthenticator) Authenticate(ctx context.Context, raw string) (api.Identity, error) {
	claims, err := a.Parser.Parse(ctx, raw, "")
	if err != nil {
		return api.Identity{}, err
	}
	return api.Identity{Subject: claims.Subject, Audience: claims.Audience, Permissions: claims.Permissions, Context: claims}, nil
}

type Readiness struct {
	db          *database.Store
	engine      *engine.Engine
	signer      signing.Signer
	fingerprint string
	stopping    atomic.Bool
}

func NewReadiness(db *database.Store, fga *engine.Engine, signer signing.Signer, fingerprint string) *Readiness {
	return &Readiness{db: db, engine: fga, signer: signer, fingerprint: fingerprint}
}
func (r *Readiness) Stop() { r.stopping.Store(true) }
func (r *Readiness) Check(ctx context.Context) error {
	if r == nil || r.stopping.Load() {
		return errors.New("service is stopping")
	}
	if err := r.db.Ping(ctx); err != nil {
		return err
	}
	if _, err := r.engine.VerifyFingerprint(ctx, r.fingerprint); err != nil {
		return err
	}
	if _, err := r.signer.PublicJWK(ctx); err != nil {
		return err
	}
	return nil
}

type Backend struct {
	Service        *service.Service
	DB             *database.Store
	Exchanger      *token.Exchanger
	Issuer         *token.Issuer
	ReadyState     *Readiness
	IssuerURL      string
	ReconcileBatch int
}

func (b *Backend) OAuthMetadata(context.Context) (api.OAuthMetadata, error) {
	return api.OAuthMetadata{Issuer: b.IssuerURL, TokenEndpoint: b.IssuerURL + "/oauth2/token", JWKSURI: b.IssuerURL + "/.well-known/jwks.json", GrantTypesSupported: []string{token.GrantTypeTokenExchange}, SubjectTypes: []string{"public"}}, nil
}
func (b *Backend) JWKS(ctx context.Context) (map[string]any, error) { return b.Issuer.JWKS(ctx) }
func (b *Backend) Exchange(ctx context.Context, in api.TokenExchangeRequest) (api.TokenExchangeResponse, error) {
	out, claims, err := b.Exchanger.Exchange(ctx, token.ExchangeRequest{GrantType: in.GrantType, SubjectToken: in.SubjectToken, SubjectTokenType: in.SubjectTokenType, ActorToken: in.ActorToken, ActorTokenType: in.ActorTokenType, Audience: in.Audience})
	if err != nil {
		_, _ = b.DB.AppendAuditEvent(ctx, database.AuditEvent{RequestID: stringPtr(api.RequestIDFromContext(ctx)), Operation: "token.exchange", Target: in.Audience, Result: "failure", Details: json.RawMessage(`{"category":"invalid_request"}`)})
		return api.TokenExchangeResponse{}, api.Error(http.StatusBadRequest, "invalid_request", err.Error())
	}
	actor := claims.Subject
	if _, auditErr := b.DB.AppendAuditEvent(ctx, database.AuditEvent{RequestID: stringPtr(api.RequestIDFromContext(ctx)), ActorPrincipal: stringPtr(actor), Operation: "token.exchange", Target: in.Audience, Result: "success"}); auditErr != nil {
		return api.TokenExchangeResponse{}, auditErr
	}
	return api.TokenExchangeResponse(out), nil
}

func (b *Backend) AuditAuthenticationFailure(ctx context.Context, requestID, category string) {
	_, _ = b.DB.AppendAuditEvent(ctx, database.AuditEvent{RequestID: stringPtr(requestID), Operation: "management.authentication", Target: "management-api", Result: "failure", Details: json.RawMessage(fmt.Sprintf(`{"category":%q}`, category))})
}
func (b *Backend) Ready(ctx context.Context) error { return b.ReadyState.Check(ctx) }

func (b *Backend) CreateAudience(ctx context.Context, id api.Identity, in api.Audience) (api.Audience, error) {
	mode := database.DelegationMode(in.Delegation.Mode)
	if !in.Delegation.Enabled {
		mode = database.DelegationDisabled
	}
	out, err := b.Service.PutAudience(ctx, mutation(ctx, id), database.Audience{ID: in.ID, DisplayName: in.DisplayName, TokenTTLSeconds: int(in.TokenTTLSeconds), DelegationMode: mode})
	if err == nil {
		err = b.flush(ctx)
	}
	return audienceAPI(out), domainError(err)
}
func (b *Backend) ListAudiences(ctx context.Context, _ api.Identity) ([]api.Audience, error) {
	values, err := b.Service.Audiences(ctx, 1000, 0)
	if err != nil {
		return nil, domainError(err)
	}
	out := make([]api.Audience, len(values))
	for i, v := range values {
		out[i] = audienceAPI(v)
	}
	return out, nil
}
func (b *Backend) GetAudience(ctx context.Context, _ api.Identity, id string) (api.Audience, error) {
	v, e := b.Service.Audience(ctx, id)
	return audienceAPI(v), domainError(e)
}
func (b *Backend) PatchAudience(ctx context.Context, identity api.Identity, id string, patch api.AudiencePatch) (api.Audience, error) {
	v, err := b.Service.Audience(ctx, id)
	if err != nil {
		return api.Audience{}, domainError(err)
	}
	if patch.DisplayName != nil {
		v.DisplayName = *patch.DisplayName
	}
	if patch.TokenTTLSeconds != nil {
		v.TokenTTLSeconds = int(*patch.TokenTTLSeconds)
	}
	if patch.Delegation != nil {
		v.DelegationMode = database.DelegationMode(patch.Delegation.Mode)
		if !patch.Delegation.Enabled {
			v.DelegationMode = database.DelegationDisabled
		}
	}
	out, err := b.Service.PutAudience(ctx, mutation(ctx, identity), v)
	if err == nil {
		err = b.flush(ctx)
	}
	return audienceAPI(out), domainError(err)
}
func (b *Backend) DeleteAudience(ctx context.Context, id api.Identity, audienceID string) error {
	_, err := b.Service.DeleteAudience(ctx, mutation(ctx, id), audienceID)
	if err == nil {
		err = b.flush(ctx)
	}
	return domainError(err)
}

func (b *Backend) CreateResource(ctx context.Context, id api.Identity, in api.Resource) (api.Resource, error) {
	metadata, _ := json.Marshal(in.Metadata)
	relationships := make(map[string][]database.ResourceRef, len(in.Relationships))
	for name, targets := range in.Relationships {
		for _, target := range targets {
			relationships[name] = append(relationships[name], resourceDB(target))
		}
	}
	v, err := b.Service.CreateResource(ctx, mutation(ctx, id), service.CreateResourceRequest{Resource: database.Resource{ResourceRef: database.ResourceRef{Type: in.Type, ID: in.ID}, Metadata: metadata}, Relationships: relationships})
	if err != nil {
		return api.Resource{}, domainError(err)
	}
	if err = b.flush(ctx); err != nil {
		return api.Resource{}, err
	}
	return b.resourceAPI(ctx, v)
}
func (b *Backend) GetResource(ctx context.Context, _ api.Identity, ref api.ResourceRef) (api.Resource, error) {
	v, e := b.Service.Resource(ctx, resourceDB(ref))
	if e != nil {
		return api.Resource{}, domainError(e)
	}
	return b.resourceAPI(ctx, v)
}
func (b *Backend) PatchResource(ctx context.Context, id api.Identity, ref api.ResourceRef, patch api.ResourcePatch) (api.Resource, error) {
	metadata, err := json.Marshal(patch.Metadata)
	if err != nil {
		return api.Resource{}, api.Error(http.StatusBadRequest, "invalid_metadata", "metadata is invalid")
	}
	v, err := b.Service.UpdateResource(ctx, mutation(ctx, id), database.Resource{ResourceRef: resourceDB(ref), Metadata: metadata})
	if err != nil {
		return api.Resource{}, domainError(err)
	}
	if err = b.flush(ctx); err != nil {
		return api.Resource{}, err
	}
	return b.resourceAPI(ctx, v)
}
func (b *Backend) DeleteResource(ctx context.Context, id api.Identity, ref api.ResourceRef) error {
	_, e := b.Service.DeleteResource(ctx, mutation(ctx, id), resourceDB(ref))
	if e == nil {
		e = b.flush(ctx)
	}
	return domainError(e)
}
func (b *Backend) PutRelationship(ctx context.Context, id api.Identity, source api.ResourceRef, relation string, in api.RelationshipMutation) error {
	targets := in.AllTargets()
	refs := make([]database.ResourceRef, len(targets))
	for i, target := range targets {
		refs[i] = resourceDB(target)
	}
	err := b.Service.SetRelationship(ctx, mutation(ctx, id), service.RelationshipRequest{Source: resourceDB(source), Relation: relation, Targets: refs})
	if err == nil {
		err = b.flush(ctx)
	}
	return domainError(err)
}
func (b *Backend) DeleteRelationship(ctx context.Context, id api.Identity, source api.ResourceRef, relation string, in api.RelationshipMutation) error {
	targets := in.AllTargets()
	if len(targets) == 0 {
		relationships, err := b.DB.Relationships(ctx, resourceDB(source))
		if err != nil {
			return err
		}
		for _, r := range relationships {
			if r.Relation == relation {
				targets = append(targets, api.ResourceRef{Type: r.Target.Type, ID: r.Target.ID})
			}
		}
	}
	for i, target := range targets {
		m := mutation(ctx, id)
		m.OperationID = fmt.Sprintf("%s:%d", m.OperationID, i)
		if _, err := b.Service.RemoveRelationship(ctx, m, resourceDB(source), relation, resourceDB(target)); err != nil {
			return domainError(err)
		}
	}
	return domainError(b.flush(ctx))
}

func (b *Backend) CreateGroup(ctx context.Context, id api.Identity, in api.Group) (api.Group, error) {
	v, e := b.Service.CreateGroup(ctx, mutation(ctx, id), database.Group{ID: in.ID, DisplayName: in.DisplayName})
	if e == nil {
		e = b.flush(ctx)
	}
	return api.Group{ID: v.ID, DisplayName: v.DisplayName}, domainError(e)
}
func (b *Backend) GetGroup(ctx context.Context, _ api.Identity, id string) (api.Group, error) {
	v, e := b.Service.Group(ctx, id)
	return api.Group{ID: v.ID, DisplayName: v.DisplayName}, domainError(e)
}
func (b *Backend) DeleteGroup(ctx context.Context, id api.Identity, groupID string) error {
	_, e := b.Service.DeleteGroup(ctx, mutation(ctx, id), groupID)
	if e == nil {
		e = b.flush(ctx)
	}
	return domainError(e)
}
func (b *Backend) AddMember(ctx context.Context, id api.Identity, groupID string, in api.MembershipRequest) error {
	_, e := b.Service.AddMembership(ctx, mutation(ctx, id), groupID, subjectDB(in.Member))
	if e == nil {
		e = b.flush(ctx)
	}
	return domainError(e)
}
func (b *Backend) DeleteMember(ctx context.Context, id api.Identity, groupID string, in api.MembershipRequest) error {
	wanted := subjectDB(in.Member)
	members, err := b.Service.Memberships(ctx, groupID)
	if err != nil {
		return domainError(err)
	}
	for _, member := range members {
		if member.Member == wanted {
			_, err = b.Service.DeleteMembership(ctx, mutation(ctx, id), member.ID)
			if err == nil {
				err = b.flush(ctx)
			}
			return domainError(err)
		}
	}
	return api.ErrNotFound
}
func (b *Backend) CreateGrant(ctx context.Context, id api.Identity, in api.Grant) (api.Grant, error) {
	if in.ID == "" {
		in.ID = randomID()
	}
	grant := database.Grant{ID: in.ID, Subject: subjectDB(in.Subject), Role: in.Role, Resource: resourceDB(in.Resource)}
	v, e := b.Service.CreateGrant(ctx, mutation(ctx, id), service.CreateGrantRequest{Grant: grant, CreateResourceIfMissing: in.CreateResourceIfMissing})
	if e == nil {
		e = b.flush(ctx)
	}
	return grantAPI(v), domainError(e)
}
func (b *Backend) DeleteGrant(ctx context.Context, id api.Identity, grantID string) error {
	_, e := b.Service.DeleteGrant(ctx, mutation(ctx, id), grantID)
	if e == nil {
		e = b.flush(ctx)
	}
	return domainError(e)
}
func (b *Backend) ListGrants(ctx context.Context, _ api.Identity) ([]api.Grant, error) {
	values, e := b.Service.Grants(ctx, database.GrantFilter{Limit: 1000})
	if e != nil {
		return nil, e
	}
	out := make([]api.Grant, len(values))
	for i, v := range values {
		out[i] = grantAPI(v)
	}
	return out, nil
}
func (b *Backend) Check(ctx context.Context, id api.Identity, in api.CheckRequest) (api.CheckResponse, error) {
	claims, ok := id.Context.(token.Claims)
	if !ok {
		return api.CheckResponse{}, api.Error(http.StatusUnauthorized, "invalid_token", "platform authorization context is required")
	}
	subject := database.PrincipalSubject(claims.AuthorizationContext.Subject.Source, claims.AuthorizationContext.Subject.Subject)
	var actor *database.Subject
	if claims.AuthorizationContext.Actor != nil {
		v := database.PrincipalSubject(claims.AuthorizationContext.Actor.Source, claims.AuthorizationContext.Actor.Subject)
		actor = &v
	}
	checks := make([]service.PermissionCheck, len(in.Checks))
	for i, c := range in.Checks {
		checks[i] = service.PermissionCheck{Permission: c.Permission, Resource: resourceDB(c.Resource)}
	}
	results, e := b.Service.BatchCheck(ctx, service.BatchCheckRequest{Subject: subject, Actor: actor, Mode: database.DelegationMode(claims.AuthorizationContext.Mode), Checks: checks})
	if e != nil {
		return api.CheckResponse{}, domainError(e)
	}
	out := api.CheckResponse{Results: make([]api.CheckResult, len(results))}
	for i, v := range results {
		out.Results[i] = api.CheckResult{ID: in.Checks[i].ID, Allowed: v.Allowed}
	}
	return out, nil
}

func (b *Backend) resourceAPI(ctx context.Context, v database.Resource) (api.Resource, error) {
	out := api.Resource{Type: v.Type, ID: v.ID}
	_ = json.Unmarshal(v.Metadata, &out.Metadata)
	relationships, err := b.DB.Relationships(ctx, v.ResourceRef)
	if err != nil {
		return api.Resource{}, err
	}
	out.Relationships = api.ResourceRelationships{}
	for _, r := range relationships {
		out.Relationships[r.Relation] = append(out.Relationships[r.Relation], api.ResourceRef{Type: r.Target.Type, ID: r.Target.ID})
	}
	return out, nil
}
func audienceAPI(v database.Audience) api.Audience {
	out := api.Audience{ID: v.ID, DisplayName: v.DisplayName, TokenTTLSeconds: int64(v.TokenTTLSeconds)}
	out.Delegation.Mode = string(v.DelegationMode)
	out.Delegation.Enabled = v.DelegationMode != database.DelegationDisabled
	return out
}
func resourceDB(v api.ResourceRef) database.ResourceRef {
	return database.ResourceRef{Type: v.Type, ID: v.ID}
}
func subjectDB(v api.Subject) database.Subject {
	if v.Type == "group" {
		return database.GroupSubject(v.Group)
	}
	return database.PrincipalSubject(v.Source, v.Subject)
}
func subjectAPI(v database.Subject) api.Subject {
	if v.Kind == "group" {
		return api.Subject{Type: "group", Group: v.GroupID}
	}
	return api.Subject{Type: "principal", Source: v.Source, Subject: v.Principal}
}
func grantAPI(v database.Grant) api.Grant {
	return api.Grant{ID: v.ID, Subject: subjectAPI(v.Subject), Role: v.Role, Resource: api.ResourceRef{Type: v.Resource.Type, ID: v.Resource.ID}}
}
func mutation(ctx context.Context, id api.Identity) service.Mutation {
	return service.Mutation{RequestID: api.RequestIDFromContext(ctx), Actor: id.Subject, OperationID: api.RequestIDFromContext(ctx)}
}
func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
func domainError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, database.ErrNotFound) {
		return api.ErrNotFound
	}
	if errors.Is(err, database.ErrCardinality) {
		return api.Error(http.StatusBadRequest, "invalid_request", err.Error())
	}
	message := err.Error()
	validationMarkers := []string{" is required", "must be positive", "unknown resource type", "unknown relationship", "unknown permission", "unknown role", "unsupported delegation mode", "unsupported member kind", "unsupported subject kind", "does not apply", "has no permissions applicable", "required relationship", "relationship target", "would create a cycle", "permits one target", "duplicate relationship target", "invalid resource type", "invalid \"", "delegated authorization is disabled", "cannot implicitly create resource", "use the audience", "use the group"}
	for _, marker := range validationMarkers {
		if strings.Contains(message, marker) {
			return api.Error(http.StatusBadRequest, "invalid_request", message)
		}
	}
	return err
}

func (b *Backend) flush(ctx context.Context) error {
	batch := b.ReconcileBatch
	if batch <= 0 {
		batch = 100
	}
	return DrainOutbox(ctx, b.Service, batch, 3)
}

type TokenAudienceLookup struct{ Service *service.Service }

func (a TokenAudienceLookup) Audience(ctx context.Context, id string) (token.Audience, error) {
	v, e := a.Service.Audience(ctx, id)
	return token.Audience{ID: v.ID, TokenTTL: time.Duration(v.TokenTTLSeconds) * time.Second, Delegation: token.DelegationMode(v.DelegationMode)}, e
}

type TokenPermissionLookup struct{ Service *service.Service }

func (p TokenPermissionLookup) AudiencePermissions(ctx context.Context, principal authn.Principal, audience string) ([]string, error) {
	return p.Service.AudiencePermissions(ctx, database.PrincipalSubject(principal.Source, principal.Subject), nil, audience)
}
