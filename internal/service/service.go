package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/authorization/compiler"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

type Service struct {
	db     *database.Store
	config *config.Config
	engine Engine
}

func New(db *database.Store, cfg *config.Config, engine Engine) (*Service, error) {
	if db == nil {
		return nil, errors.New("service: database is required")
	}
	if cfg == nil {
		return nil, errors.New("service: configuration is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("service: invalid configuration: %w", err)
	}
	if engine == nil {
		return nil, errors.New("service: authorization engine is required")
	}
	return &Service{db: db, config: cfg, engine: engine}, nil
}

func (s *Service) CreateResource(ctx context.Context, mutation Mutation, req CreateResourceRequest) (database.Resource, error) {
	if err := validateMutation(mutation); err != nil {
		return database.Resource{}, err
	}
	if err := s.validateResourceType(req.Resource.Type); err != nil {
		return database.Resource{}, err
	}
	if req.Resource.ID == "" {
		return database.Resource{}, errors.New("resource id is required")
	}
	definition := s.resourceDefinition(req.Resource.Type)
	for relation, rule := range definition.Relationships {
		if rule.Required && len(req.Relationships[relation]) == 0 {
			return database.Resource{}, fmt.Errorf("required relationship %q is missing", relation)
		}
	}
	for relation, targets := range req.Relationships {
		if err := s.validateRelationship(req.Resource.ResourceRef, relation, targets); err != nil {
			return database.Resource{}, err
		}
	}
	created, err := s.db.CreateResource(ctx, req.Resource)
	if err != nil {
		return database.Resource{}, err
	}
	for relation, targets := range req.Relationships {
		if _, err := s.setRelationship(ctx, mutation, RelationshipRequest{Source: created.ResourceRef, Relation: relation, Targets: targets}, false); err != nil {
			_, _ = s.db.DeleteResource(ctx, created.ResourceRef, mutation.OperationID+":rollback")
			return database.Resource{}, fmt.Errorf("create initial relationship: %w", err)
		}
	}
	if err := s.audit(ctx, mutation, "resource.created", objectLabel(created.ResourceRef), "success", nil, created); err != nil {
		return database.Resource{}, err
	}
	return created, nil
}

func (s *Service) Resource(ctx context.Context, ref database.ResourceRef) (database.Resource, error) {
	if err := s.validateResourceType(ref.Type); err != nil {
		return database.Resource{}, err
	}
	return s.db.Resource(ctx, ref)
}

func (s *Service) UpdateResource(ctx context.Context, mutation Mutation, resource database.Resource) (database.Resource, error) {
	if err := validateMutation(mutation); err != nil {
		return database.Resource{}, err
	}
	if err := s.validateResourceType(resource.Type); err != nil {
		return database.Resource{}, err
	}
	if resource.Type == "audience" || resource.Type == "group" {
		return database.Resource{}, fmt.Errorf("use the %s update operation", resource.Type)
	}
	prior, err := s.db.Resource(ctx, resource.ResourceRef)
	if err != nil {
		return database.Resource{}, err
	}
	updated, err := s.db.UpdateResource(ctx, resource)
	if err != nil {
		return database.Resource{}, err
	}
	if err := s.audit(ctx, mutation, "resource.updated", objectLabel(resource.ResourceRef), "success", prior, updated); err != nil {
		return database.Resource{}, err
	}
	return updated, nil
}

func (s *Service) Resources(ctx context.Context, resourceType string, limit, offset int) ([]database.Resource, error) {
	if resourceType != "" {
		if err := s.validateResourceType(resourceType); err != nil {
			return nil, err
		}
	}
	return s.db.Resources(ctx, resourceType, limit, offset)
}

func (s *Service) DeleteResource(ctx context.Context, mutation Mutation, ref database.ResourceRef) (bool, error) {
	if err := validateMutation(mutation); err != nil {
		return false, err
	}
	if err := s.validateResourceType(ref.Type); err != nil {
		return false, err
	}
	if ref.Type == "audience" || ref.Type == "group" {
		return false, fmt.Errorf("use the %s deletion operation", ref.Type)
	}
	deleted, err := s.db.DeleteResource(ctx, ref, mutation.OperationID)
	if err != nil {
		return false, err
	}
	if deleted {
		err = s.audit(ctx, mutation, "resource.deleted", objectLabel(ref), "success", ref, nil)
	}
	return deleted, err
}

func (s *Service) SetRelationship(ctx context.Context, mutation Mutation, req RelationshipRequest) error {
	if err := validateMutation(mutation); err != nil {
		return err
	}
	_, err := s.setRelationship(ctx, mutation, req, true)
	return err
}

func (s *Service) setRelationship(ctx context.Context, mutation Mutation, req RelationshipRequest, doAudit bool) ([]database.Relationship, error) {
	if err := s.validateRelationship(req.Source, req.Relation, req.Targets); err != nil {
		return nil, err
	}
	rule := s.resourceDefinition(req.Source.Type).Relationships[req.Relation]
	existing, err := s.db.Relationships(ctx, req.Source)
	if err != nil {
		return nil, err
	}
	var current []database.Relationship
	for _, relationship := range existing {
		if relationship.Relation == req.Relation {
			current = append(current, relationship)
		}
	}
	wanted := make(map[database.ResourceRef]bool, len(req.Targets))
	for _, target := range req.Targets {
		if _, err := s.db.Resource(ctx, target); err != nil {
			return nil, fmt.Errorf("relationship target %s: %w", objectLabel(target), err)
		}
		wanted[target] = true
	}
	for i, relationship := range current {
		if wanted[relationship.Target] {
			continue
		}
		op := database.TupleOperation{OperationID: fmt.Sprintf("%s:%s:delete:%d", mutation.OperationID, req.Relation, i), Action: "delete", Object: relationship.Tuple.Object, Relation: relationship.Tuple.Relation, Subject: relationship.Tuple.Subject}
		if _, err := s.db.DeleteRelationship(ctx, req.Source, req.Relation, relationship.Target, op); err != nil {
			return nil, err
		}
	}
	for i, target := range req.Targets {
		tuple, err := relationshipTuple(req.Source, req.Relation, target)
		if err != nil {
			return nil, err
		}
		relationship := database.Relationship{Source: req.Source, Relation: req.Relation, Target: target, Cardinality: database.Cardinality(rule.Cardinality), Tuple: tuple}
		op := database.TupleOperation{OperationID: fmt.Sprintf("%s:%s:write:%d", mutation.OperationID, req.Relation, i)}
		if err := s.db.PutRelationship(ctx, relationship, op); err != nil {
			return nil, err
		}
	}
	if doAudit {
		if err := s.audit(ctx, mutation, "resource.relationship.changed", objectLabel(req.Source)+"#"+req.Relation, "success", current, req.Targets); err != nil {
			return nil, err
		}
	}
	return current, nil
}

func (s *Service) RemoveRelationship(ctx context.Context, mutation Mutation, source database.ResourceRef, relation string, target database.ResourceRef) (bool, error) {
	if err := validateMutation(mutation); err != nil {
		return false, err
	}
	if err := s.validateRelationship(source, relation, []database.ResourceRef{target}); err != nil {
		return false, err
	}
	definition := s.resourceDefinition(source.Type)
	rule, ok := definition.Relationships[relation]
	if !ok {
		return false, fmt.Errorf("unknown relationship %q for resource type %q", relation, source.Type)
	}
	if rule.Required {
		current, err := s.db.Relationships(ctx, source)
		if err != nil {
			return false, err
		}
		count := 0
		for _, r := range current {
			if r.Relation == relation {
				count++
			}
		}
		if count <= 1 {
			return false, fmt.Errorf("relationship %q is required", relation)
		}
	}
	tuple, err := relationshipTuple(source, relation, target)
	if err != nil {
		return false, err
	}
	deleted, err := s.db.DeleteRelationship(ctx, source, relation, target, database.TupleOperation{OperationID: mutation.OperationID, Action: "delete", Object: tuple.Object, Relation: tuple.Relation, Subject: tuple.Subject})
	if err == nil && deleted {
		err = s.audit(ctx, mutation, "resource.relationship.changed", objectLabel(source)+"#"+relation, "success", target, nil)
	}
	return deleted, err
}

func (s *Service) validateRelationship(source database.ResourceRef, relation string, targets []database.ResourceRef) error {
	if err := s.validateResourceType(source.Type); err != nil {
		return err
	}
	rule, ok := s.resourceDefinition(source.Type).Relationships[relation]
	if !ok {
		return fmt.Errorf("unknown relationship %q for resource type %q", relation, source.Type)
	}
	if rule.Required && len(targets) == 0 {
		return fmt.Errorf("relationship %q is required", relation)
	}
	if rule.Cardinality == "one" && len(targets) > 1 {
		return fmt.Errorf("relationship %q permits one target", relation)
	}
	seen := map[database.ResourceRef]bool{}
	for _, target := range targets {
		if seen[target] {
			return fmt.Errorf("duplicate relationship target %s", objectLabel(target))
		}
		seen[target] = true
		if target.ID == "" || !slices.Contains(rule.Targets, target.Type) {
			return fmt.Errorf("invalid %q relationship target %s", relation, objectLabel(target))
		}
	}
	return nil
}

func (s *Service) validateResourceType(resourceType string) error {
	if resourceType == "audience" || resourceType == "group" {
		return nil
	}
	if _, ok := s.config.Resources[resourceType]; !ok {
		return fmt.Errorf("unknown resource type %q", resourceType)
	}
	return nil
}

func (s *Service) resourceDefinition(resourceType string) config.Resource {
	return s.config.Resources[resourceType]
}

func relationshipTuple(source database.ResourceRef, relation string, target database.ResourceRef) (database.AuthorizationTuple, error) {
	object, err := ResourceObject(source)
	if err != nil {
		return database.AuthorizationTuple{}, err
	}
	subject, err := ResourceObject(target)
	if err != nil {
		return database.AuthorizationTuple{}, err
	}
	return database.AuthorizationTuple{Object: object, Relation: relation, Subject: subject}, nil
}

func grantTuple(g database.Grant) (database.AuthorizationTuple, error) {
	object, err := ResourceObject(g.Resource)
	if err != nil {
		return database.AuthorizationTuple{}, err
	}
	subject, err := subjectTuple(g.Subject)
	if err != nil {
		return database.AuthorizationTuple{}, err
	}
	return database.AuthorizationTuple{Object: object, Relation: compiler.RoleRelation(g.Role), Subject: subject}, nil
}

func membershipTuple(groupID string, member database.Subject) (database.AuthorizationTuple, error) {
	object, err := ResourceObject(database.ResourceRef{Type: "group", ID: groupID})
	if err != nil {
		return database.AuthorizationTuple{}, err
	}
	subject, err := subjectTuple(member)
	if err != nil {
		return database.AuthorizationTuple{}, err
	}
	return database.AuthorizationTuple{Object: object, Relation: "member", Subject: subject}, nil
}

func (s *Service) audit(ctx context.Context, mutation Mutation, operation, target, result string, before, after any) error {
	requestID, actor := nullableString(mutation.RequestID), nullableString(mutation.Actor)
	previous, _ := json.Marshal(before)
	next, _ := json.Marshal(after)
	_, err := s.db.AppendAuditEvent(ctx, database.AuditEvent{RequestID: requestID, ActorPrincipal: actor, Operation: operation, Target: target, Result: result, PreviousValue: nullValue(previous, before), NewValue: nullValue(next, after)})
	return err
}

func nullableString(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
func nullValue(raw []byte, value any) []byte {
	if value == nil {
		return nil
	}
	return raw
}
func objectLabel(ref database.ResourceRef) string { return ref.Type + ":" + ref.ID }
func contains(values []string, value string) bool { return slices.Contains(values, value) }
func nonempty(value, field string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

func validateMutation(m Mutation) error { return nonempty(m.OperationID, "operation id") }
