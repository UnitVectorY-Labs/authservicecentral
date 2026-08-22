// Package compiler translates deployment configuration into an OpenFGA 1.1
// authorization model. The returned model is JSON-compatible with OpenFGA's
// WriteAuthorizationModel request body (apart from the store identifier).
package compiler

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
)

type Model struct {
	SchemaVersion   string           `json:"schema_version"`
	TypeDefinitions []TypeDefinition `json:"type_definitions"`
}

type TypeDefinition struct {
	Type      string             `json:"type"`
	Relations map[string]Userset `json:"relations,omitempty"`
	Metadata  *TypeMetadata      `json:"metadata,omitempty"`
}

type TypeMetadata struct {
	Relations map[string]RelationMetadata `json:"relations,omitempty"`
}
type RelationMetadata struct {
	DirectlyRelatedUserTypes []RelationReference `json:"directly_related_user_types,omitempty"`
}
type RelationReference struct {
	Type     string  `json:"type"`
	Relation *string `json:"relation,omitempty"`
}

type Userset struct {
	This            *struct{}       `json:"this,omitempty"`
	ComputedUserset *ObjectRelation `json:"computedUserset,omitempty"`
	TupleToUserset  *TupleToUserset `json:"tupleToUserset,omitempty"`
	Union           *Usersets       `json:"union,omitempty"`
}
type ObjectRelation struct {
	Relation string `json:"relation"`
}
type TupleToUserset struct {
	Tupleset        ObjectRelation `json:"tupleset"`
	ComputedUserset ObjectRelation `json:"computedUserset"`
}
type Usersets struct {
	Child []Userset `json:"child"`
}

func Compile(c *config.Config) (*Model, error) {
	if c == nil {
		return nil, fmt.Errorf("compile authorization model: nil configuration")
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("compile authorization model: %w", err)
	}

	types := []TypeDefinition{{Type: "principal"}, groupType()}
	resourceNames := sortedKeys(c.Resources)
	resourceNames = append(resourceNames, "audience")
	sort.Strings(resourceNames)

	// A permission inherited through a relationship needs an identically named
	// computed relation on every possible target, even if it is not a public
	// permission for that target type.
	helperPermissions := map[string]map[string]bool{}
	for source, resource := range c.Resources {
		_ = source
		for _, inheritance := range resource.Inheritance {
			for _, target := range resource.Relationships[inheritance.Relationship].Targets {
				if helperPermissions[target] == nil {
					helperPermissions[target] = map[string]bool{}
				}
				for _, permission := range inheritance.Permissions {
					helperPermissions[target][permission] = true
				}
			}
		}
	}

	for _, resourceName := range resourceNames {
		resource := c.Resources[resourceName]
		relations := map[string]Userset{}
		metadata := map[string]RelationMetadata{}
		for _, relationshipName := range sortedKeys(resource.Relationships) {
			relationship := resource.Relationships[relationshipName]
			relations[relationshipName] = direct()
			refs := make([]RelationReference, 0, len(relationship.Targets))
			for _, target := range sortedStrings(relationship.Targets) {
				refs = append(refs, RelationReference{Type: target})
			}
			metadata[relationshipName] = RelationMetadata{DirectlyRelatedUserTypes: refs}
		}

		permissionSet := map[string]bool{}
		for permissionName, permission := range c.Permissions {
			if contains(permission.Resources, resourceName) {
				permissionSet[permissionName] = true
			}
		}
		for permissionName := range helperPermissions[resourceName] {
			permissionSet[permissionName] = true
		}

		roleSet := map[string]bool{}
		for roleName, role := range c.Roles {
			for _, permissionName := range role.Permissions {
				if permissionSet[permissionName] {
					roleSet[roleName] = true
				}
			}
		}
		for _, roleName := range sortedBoolKeys(roleSet) {
			name := roleRelation(roleName)
			relations[name] = direct()
			member := "member"
			metadata[name] = RelationMetadata{DirectlyRelatedUserTypes: []RelationReference{{Type: "principal"}, {Type: "group", Relation: &member}}}
		}

		for _, permissionName := range sortedBoolKeys(permissionSet) {
			children := []Userset{}
			for _, roleName := range sortedKeys(c.Roles) {
				if contains(c.Roles[roleName].Permissions, permissionName) && roleSet[roleName] {
					children = append(children, computed(roleRelation(roleName)))
				}
			}
			// Only public/applicable permissions inherit. Helper relations on a
			// target intentionally contain direct role expansion only.
			if definition, ok := c.Permissions[permissionName]; ok && contains(definition.Resources, resourceName) {
				for _, inheritance := range resource.Inheritance {
					if contains(inheritance.Permissions, permissionName) {
						children = append(children, Userset{TupleToUserset: &TupleToUserset{Tupleset: ObjectRelation{Relation: inheritance.Relationship}, ComputedUserset: ObjectRelation{Relation: permissionRelation(permissionName)}}})
					}
				}
			}
			relations[permissionRelation(permissionName)] = union(children)
		}
		t := TypeDefinition{Type: resourceName, Relations: relations}
		if len(metadata) > 0 {
			t.Metadata = &TypeMetadata{Relations: metadata}
		}
		types = append(types, t)
	}
	model := &Model{SchemaVersion: "1.1", TypeDefinitions: types}
	if err := model.Validate(); err != nil {
		return nil, fmt.Errorf("compile authorization model: generated model: %w", err)
	}
	return model, nil
}

func (m *Model) JSON() ([]byte, error) { return json.MarshalIndent(m, "", "  ") }
func (m *Model) Validate() error {
	if m == nil || m.SchemaVersion != "1.1" {
		return fmt.Errorf("schema_version must be 1.1")
	}
	types := map[string]TypeDefinition{}
	for _, definition := range m.TypeDefinitions {
		if _, exists := types[definition.Type]; exists {
			return fmt.Errorf("duplicate type %q", definition.Type)
		}
		types[definition.Type] = definition
	}
	for _, definition := range m.TypeDefinitions {
		for relation, rewrite := range definition.Relations {
			if err := validateRewrite(types, definition, relation, rewrite); err != nil {
				return err
			}
		}
	}
	return nil
}
func PermissionRelation(permission string) string { return permissionRelation(permission) }
func RoleRelation(role string) string             { return roleRelation(role) }

func groupType() TypeDefinition {
	member := "member"
	return TypeDefinition{Type: "group", Relations: map[string]Userset{"member": direct()}, Metadata: &TypeMetadata{Relations: map[string]RelationMetadata{"member": {DirectlyRelatedUserTypes: []RelationReference{{Type: "principal"}, {Type: "group", Relation: &member}}}}}}
}
func direct() Userset { return Userset{This: &struct{}{}} }
func computed(relation string) Userset {
	return Userset{ComputedUserset: &ObjectRelation{Relation: relation}}
}
func union(children []Userset) Userset {
	if len(children) == 1 {
		return children[0]
	}
	return Userset{Union: &Usersets{Child: children}}
}
func permissionRelation(name string) string {
	return "permission_" + strings.ReplaceAll(name, ".", "_")
}
func roleRelation(name string) string { return "role_" + name }
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func sortedBoolKeys(m map[string]bool) []string { return sortedKeys(m) }
func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func validateRewrite(types map[string]TypeDefinition, definition TypeDefinition, relation string, rewrite Userset) error {
	if rewrite.ComputedUserset != nil {
		if _, ok := definition.Relations[rewrite.ComputedUserset.Relation]; !ok {
			return fmt.Errorf("type %q relation %q references unknown computed relation %q", definition.Type, relation, rewrite.ComputedUserset.Relation)
		}
	}
	if rewrite.TupleToUserset != nil {
		tupleset := rewrite.TupleToUserset.Tupleset.Relation
		if _, ok := definition.Relations[tupleset]; !ok {
			return fmt.Errorf("type %q relation %q references unknown tupleset %q", definition.Type, relation, tupleset)
		}
		if definition.Metadata == nil {
			return fmt.Errorf("type %q tupleset %q has no type metadata", definition.Type, tupleset)
		}
		metadata, ok := definition.Metadata.Relations[tupleset]
		if !ok {
			return fmt.Errorf("type %q tupleset %q has no type metadata", definition.Type, tupleset)
		}
		for _, ref := range metadata.DirectlyRelatedUserTypes {
			target, ok := types[ref.Type]
			if !ok {
				return fmt.Errorf("tupleset %q references unknown type %q", tupleset, ref.Type)
			}
			if _, ok := target.Relations[rewrite.TupleToUserset.ComputedUserset.Relation]; !ok {
				return fmt.Errorf("type %q lacks inherited relation %q", ref.Type, rewrite.TupleToUserset.ComputedUserset.Relation)
			}
		}
	}
	if rewrite.Union != nil {
		if len(rewrite.Union.Child) == 0 {
			return fmt.Errorf("type %q relation %q has an empty union", definition.Type, relation)
		}
		for _, child := range rewrite.Union.Child {
			if err := validateRewrite(types, definition, relation, child); err != nil {
				return err
			}
		}
	}
	return nil
}
