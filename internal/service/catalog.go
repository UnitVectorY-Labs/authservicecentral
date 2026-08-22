package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/authorization/compiler"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

func (s *Service) PutAudience(ctx context.Context, mutation Mutation, audience database.Audience) (database.Audience, error) {
	if err := validateMutation(mutation); err != nil {
		return database.Audience{}, err
	}
	if err := nonempty(audience.ID, "audience id"); err != nil {
		return database.Audience{}, err
	}
	if audience.TokenTTLSeconds <= 0 {
		return database.Audience{}, errors.New("audience token TTL must be positive")
	}
	if audience.DelegationMode == "" {
		audience.DelegationMode = database.DelegationDisabled
	}
	switch audience.DelegationMode {
	case database.DelegationDisabled, database.DelegationSubject, database.DelegationIntersection, database.DelegationActor, database.DelegationUnion:
	default:
		return database.Audience{}, fmt.Errorf("unsupported delegation mode %q", audience.DelegationMode)
	}
	prior, priorErr := s.db.Audience(ctx, audience.ID)
	if priorErr != nil && !errors.Is(priorErr, database.ErrNotFound) {
		return database.Audience{}, priorErr
	}
	saved, err := s.db.PutAudience(ctx, audience)
	if err != nil {
		return database.Audience{}, err
	}
	operation := "audience.created"
	var before any
	if priorErr == nil {
		operation, before = "audience.updated", prior
	}
	if err := s.audit(ctx, mutation, operation, objectLabel(database.ResourceRef{Type: "audience", ID: audience.ID}), "success", before, saved); err != nil {
		return database.Audience{}, err
	}
	return saved, nil
}

func (s *Service) Audience(ctx context.Context, id string) (database.Audience, error) {
	return s.db.Audience(ctx, id)
}
func (s *Service) Audiences(ctx context.Context, limit, offset int) ([]database.Audience, error) {
	return s.db.Audiences(ctx, limit, offset)
}

func (s *Service) DeleteAudience(ctx context.Context, mutation Mutation, id string) (bool, error) {
	if err := validateMutation(mutation); err != nil {
		return false, err
	}
	if _, err := s.db.Audience(ctx, id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	ref := database.ResourceRef{Type: "audience", ID: id}
	// DeleteResource captures all grant/relationship tuples before the catalog
	// row disappears; DeleteAudience then removes the audience metadata.
	_, err := s.db.DeleteResource(ctx, ref, mutation.OperationID)
	if err != nil {
		return false, err
	}
	_, err = s.db.DeleteAudience(ctx, id)
	if err == nil {
		err = s.audit(ctx, mutation, "audience.deleted", objectLabel(ref), "success", id, nil)
	}
	return err == nil, err
}

func (s *Service) CreateGroup(ctx context.Context, mutation Mutation, group database.Group) (database.Group, error) {
	if err := validateMutation(mutation); err != nil {
		return database.Group{}, err
	}
	if err := nonempty(group.ID, "group id"); err != nil {
		return database.Group{}, err
	}
	created, err := s.db.CreateGroup(ctx, group)
	if err != nil {
		return database.Group{}, err
	}
	if err := s.audit(ctx, mutation, "group.created", objectLabel(database.ResourceRef{Type: "group", ID: group.ID}), "success", nil, created); err != nil {
		return database.Group{}, err
	}
	return created, nil
}

func (s *Service) Group(ctx context.Context, id string) (database.Group, error) {
	return s.db.Group(ctx, id)
}
func (s *Service) Memberships(ctx context.Context, id string) ([]database.Membership, error) {
	return s.db.Memberships(ctx, id)
}

func (s *Service) DeleteGroup(ctx context.Context, mutation Mutation, id string) (bool, error) {
	if err := validateMutation(mutation); err != nil {
		return false, err
	}
	deleted, err := s.db.DeleteGroup(ctx, id, mutation.OperationID)
	if err == nil && deleted {
		err = s.audit(ctx, mutation, "group.deleted", objectLabel(database.ResourceRef{Type: "group", ID: id}), "success", id, nil)
	}
	return deleted, err
}

func (s *Service) AddMembership(ctx context.Context, mutation Mutation, groupID string, member database.Subject) (database.Membership, error) {
	if err := validateMutation(mutation); err != nil {
		return database.Membership{}, err
	}
	if _, err := s.db.Group(ctx, groupID); err != nil {
		return database.Membership{}, fmt.Errorf("parent group: %w", err)
	}
	if member.Kind == "group" {
		if _, err := s.db.Group(ctx, member.GroupID); err != nil {
			return database.Membership{}, fmt.Errorf("member group: %w", err)
		}
		cycle, err := s.membershipReaches(ctx, member.GroupID, groupID, map[string]bool{})
		if err != nil {
			return database.Membership{}, err
		}
		if cycle {
			return database.Membership{}, errors.New("nested group membership would create a cycle")
		}
	} else if _, err := PrincipalObject(member.Source, member.Principal); member.Kind != "principal" || err != nil {
		if err != nil {
			return database.Membership{}, err
		}
		return database.Membership{}, fmt.Errorf("unsupported member kind %q", member.Kind)
	}
	tuple, err := membershipTuple(groupID, member)
	if err != nil {
		return database.Membership{}, err
	}
	membership := database.Membership{GroupID: groupID, Member: member, Tuple: tuple}
	created, err := s.db.AddMembership(ctx, membership, database.TupleOperation{OperationID: mutation.OperationID})
	if err != nil {
		return database.Membership{}, err
	}
	if err := s.audit(ctx, mutation, "group.membership.added", objectLabel(database.ResourceRef{Type: "group", ID: groupID}), "success", nil, created); err != nil {
		return database.Membership{}, err
	}
	return created, nil
}

func (s *Service) DeleteMembership(ctx context.Context, mutation Mutation, id int64) (bool, error) {
	if err := validateMutation(mutation); err != nil {
		return false, err
	}
	deleted, err := s.db.DeleteMembership(ctx, id, mutation.OperationID)
	if err == nil && deleted {
		err = s.audit(ctx, mutation, "group.membership.removed", fmt.Sprintf("membership:%d", id), "success", id, nil)
	}
	return deleted, err
}

func (s *Service) membershipReaches(ctx context.Context, from, wanted string, visited map[string]bool) (bool, error) {
	if from == wanted {
		return true, nil
	}
	if visited[from] {
		return false, nil
	}
	visited[from] = true
	members, err := s.db.Memberships(ctx, from)
	if err != nil {
		return false, err
	}
	for _, membership := range members {
		if membership.Member.Kind != "group" {
			continue
		}
		found, err := s.membershipReaches(ctx, membership.Member.GroupID, wanted, visited)
		if err != nil || found {
			return found, err
		}
	}
	return false, nil
}

func (s *Service) CreateGrant(ctx context.Context, mutation Mutation, req CreateGrantRequest) (database.Grant, error) {
	if err := validateMutation(mutation); err != nil {
		return database.Grant{}, err
	}
	if err := s.validateGrant(req.Grant); err != nil {
		return database.Grant{}, err
	}
	createdResource := false
	if _, err := s.db.Resource(ctx, req.Grant.Resource); err != nil {
		if !errors.Is(err, database.ErrNotFound) || !req.CreateResourceIfMissing {
			return database.Grant{}, fmt.Errorf("grant resource: %w", err)
		}
		definition := s.resourceDefinition(req.Grant.Resource.Type)
		for name, relationship := range definition.Relationships {
			if relationship.Required {
				return database.Grant{}, fmt.Errorf("cannot implicitly create resource: required relationship %q is missing", name)
			}
		}
		created, createErr := s.db.CreateResource(ctx, database.Resource{ResourceRef: req.Grant.Resource, Metadata: req.ResourceMetadata})
		if createErr != nil {
			return database.Grant{}, createErr
		}
		createdResource = true
		if auditErr := s.audit(ctx, mutation, "resource.created", objectLabel(req.Grant.Resource), "success", nil, created); auditErr != nil {
			_, _ = s.db.DeleteResource(ctx, req.Grant.Resource, mutation.OperationID+":rollback")
			return database.Grant{}, auditErr
		}
	}
	// Semantic idempotency handles retries after a response is lost.
	existing, err := s.db.Grants(ctx, database.GrantFilter{Subject: &req.Grant.Subject, Resource: &req.Grant.Resource, Role: req.Grant.Role, Limit: 2})
	if err == nil && len(existing) > 0 {
		return existing[0], nil
	}
	tuple, err := grantTuple(req.Grant)
	if err != nil {
		return database.Grant{}, err
	}
	req.Grant.Tuple = tuple
	created, err := s.db.CreateGrant(ctx, req.Grant, database.TupleOperation{OperationID: mutation.OperationID})
	if err != nil {
		if createdResource {
			_, _ = s.db.DeleteResource(ctx, req.Grant.Resource, mutation.OperationID+":rollback")
		}
		return database.Grant{}, err
	}
	if err := s.audit(ctx, mutation, "grant.added", created.ID, "success", nil, created); err != nil {
		return database.Grant{}, err
	}
	return created, nil
}

func (s *Service) DeleteGrant(ctx context.Context, mutation Mutation, id string) (bool, error) {
	if err := validateMutation(mutation); err != nil {
		return false, err
	}
	deleted, err := s.db.DeleteGrant(ctx, id, mutation.OperationID)
	if err == nil && deleted {
		err = s.audit(ctx, mutation, "grant.removed", id, "success", id, nil)
	}
	return deleted, err
}

func (s *Service) Grants(ctx context.Context, filter database.GrantFilter) ([]database.Grant, error) {
	return s.db.Grants(ctx, filter)
}

func (s *Service) validateGrant(grant database.Grant) error {
	if err := nonempty(grant.ID, "grant id"); err != nil {
		return err
	}
	if err := s.validateResourceType(grant.Resource.Type); err != nil {
		return err
	}
	role, ok := s.config.Roles[grant.Role]
	if !ok {
		return fmt.Errorf("unknown role %q", grant.Role)
	}
	applicable := false
	for _, permissionName := range role.Permissions {
		if slices.Contains(s.config.Permissions[permissionName].Resources, grant.Resource.Type) {
			applicable = true
			break
		}
	}
	if !applicable {
		return fmt.Errorf("role %q has no permissions applicable to resource type %q", grant.Role, grant.Resource.Type)
	}
	_, err := subjectTuple(grant.Subject)
	return err
}

func (s *Service) BatchCheck(ctx context.Context, req BatchCheckRequest) ([]CheckResult, error) {
	if len(req.Checks) == 0 {
		return []CheckResult{}, nil
	}
	subject, err := subjectTuple(req.Subject)
	if err != nil {
		return nil, err
	}
	if req.Subject.Kind != "principal" {
		return nil, errors.New("authorization check subject must be a principal")
	}
	var actor string
	if req.Actor != nil {
		actor, err = subjectTuple(*req.Actor)
		if err != nil {
			return nil, err
		}
		if req.Actor.Kind != "principal" {
			return nil, errors.New("authorization check actor must be a principal")
		}
		if req.Mode == database.DelegationDisabled {
			return nil, errors.New("delegated authorization is disabled")
		}
	}
	checks := make([]EngineCheck, 0, len(req.Checks)*2)
	for _, check := range req.Checks {
		permission, ok := s.config.Permissions[check.Permission]
		if !ok {
			return nil, fmt.Errorf("unknown permission %q", check.Permission)
		}
		if err := s.validateResourceType(check.Resource.Type); err != nil {
			return nil, err
		}
		if !contains(permission.Resources, check.Resource.Type) {
			return nil, fmt.Errorf("permission %q does not apply to resource type %q", check.Permission, check.Resource.Type)
		}
		object, err := ResourceObject(check.Resource)
		if err != nil {
			return nil, err
		}
		relation := compiler.PermissionRelation(check.Permission)
		checks = append(checks, EngineCheck{Subject: subject, Relation: relation, Object: object})
		if req.Actor != nil {
			checks = append(checks, EngineCheck{Subject: actor, Relation: relation, Object: object})
		}
	}
	decisions, err := s.engine.BatchCheck(ctx, checks)
	if err != nil {
		return nil, err
	}
	if len(decisions) != len(checks) {
		return nil, fmt.Errorf("authorization engine returned %d decisions for %d checks", len(decisions), len(checks))
	}
	results := make([]CheckResult, len(req.Checks))
	at := 0
	for i, check := range req.Checks {
		allowed := decisions[at]
		at++
		if req.Actor != nil {
			allowed, err = combine(req.Mode, allowed, decisions[at])
			at++
			if err != nil {
				return nil, err
			}
		}
		results[i] = CheckResult{Permission: check.Permission, Resource: check.Resource, Allowed: allowed}
	}
	return results, nil
}

func (s *Service) AudiencePermissions(ctx context.Context, subject database.Subject, actor *database.Subject, audienceID string) ([]string, error) {
	audience, err := s.db.Audience(ctx, audienceID)
	if err != nil {
		return nil, err
	}
	var permissions []string
	for name, permission := range s.config.Permissions {
		if slices.Contains(permission.Resources, "audience") {
			permissions = append(permissions, name)
		}
	}
	sort.Strings(permissions)
	checks := make([]PermissionCheck, len(permissions))
	for i, p := range permissions {
		checks[i] = PermissionCheck{Permission: p, Resource: database.ResourceRef{Type: "audience", ID: audienceID}}
	}
	results, err := s.BatchCheck(ctx, BatchCheckRequest{Subject: subject, Actor: actor, Mode: audience.DelegationMode, Checks: checks})
	if err != nil {
		return nil, err
	}
	allowed := permissions[:0]
	for _, result := range results {
		if result.Allowed {
			allowed = append(allowed, result.Permission)
		}
	}
	return allowed, nil
}

func combine(mode database.DelegationMode, subject, actor bool) (bool, error) {
	switch mode {
	case "", database.DelegationSubject:
		return subject, nil
	case database.DelegationActor:
		return actor, nil
	case database.DelegationIntersection:
		return subject && actor, nil
	case database.DelegationUnion:
		return subject || actor, nil
	case database.DelegationDisabled:
		return false, errors.New("delegated authorization is disabled")
	default:
		return false, fmt.Errorf("unknown delegation mode %q", mode)
	}
}
