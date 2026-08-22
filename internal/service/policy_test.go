package service

import (
	"testing"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

func testConfig() *config.Config {
	return &config.Config{Version: 1, Permissions: map[string]config.Permission{
		"document.read":   {Resources: []string{"document"}},
		"audience.invoke": {Resources: []string{"audience"}},
	}, Roles: map[string]config.Role{"viewer": {Permissions: []string{"document.read", "audience.invoke"}}}, Resources: map[string]config.Resource{
		"folder":   {Relationships: map[string]config.Relationship{}},
		"document": {Relationships: map[string]config.Relationship{"parent": {Targets: []string{"folder"}, Cardinality: "one", Required: true}}},
	}}
}

func TestRelationshipValidation(t *testing.T) {
	s := &Service{config: testConfig()}
	source := database.ResourceRef{Type: "document", ID: "1"}
	if err := s.validateRelationship(source, "parent", nil); err == nil {
		t.Fatal("expected required relationship error")
	}
	if err := s.validateRelationship(source, "parent", []database.ResourceRef{{Type: "folder", ID: "a"}, {Type: "folder", ID: "b"}}); err == nil {
		t.Fatal("expected cardinality error")
	}
	if err := s.validateRelationship(source, "parent", []database.ResourceRef{{Type: "document", ID: "a"}}); err == nil {
		t.Fatal("expected target type error")
	}
	if err := s.validateRelationship(source, "parent", []database.ResourceRef{{Type: "folder", ID: "a"}}); err != nil {
		t.Fatal(err)
	}
}

func TestGrantApplicability(t *testing.T) {
	s := &Service{config: testConfig()}
	base := database.Grant{ID: "g1", Role: "viewer", Subject: database.PrincipalSubject("github", "alice")}
	base.Resource = database.ResourceRef{Type: "document", ID: "1"}
	if err := s.validateGrant(base); err != nil {
		t.Fatal(err)
	}
	base.Resource = database.ResourceRef{Type: "folder", ID: "1"}
	if err := s.validateGrant(base); err == nil {
		t.Fatal("expected zero-applicable-permissions error")
	}
}

func TestDelegationCombination(t *testing.T) {
	tests := []struct {
		mode                 database.DelegationMode
		subject, actor, want bool
		wantErr              bool
	}{
		{database.DelegationSubject, true, false, true, false},
		{database.DelegationActor, true, false, false, false},
		{database.DelegationIntersection, true, false, false, false},
		{database.DelegationUnion, false, true, true, false},
		{database.DelegationDisabled, true, true, false, true},
	}
	for _, tt := range tests {
		got, err := combine(tt.mode, tt.subject, tt.actor)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("combine(%s,%v,%v)=(%v,%v)", tt.mode, tt.subject, tt.actor, got, err)
		}
	}
}
