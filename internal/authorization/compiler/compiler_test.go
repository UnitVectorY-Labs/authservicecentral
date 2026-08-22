package compiler

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
)

const schema = `version: 1
permissions:
  api.invoke: {resources: [audience]}
  document.read: {resources: [document]}
  document.write: {resources: [document]}
  folder.read: {resources: [folder]}
roles:
  reader: {permissions: [api.invoke, document.read, folder.read]}
  editor: {permissions: [document.read, document.write]}
resources:
  workspace: {relationships: {}}
  folder:
    relationships: {}
  document:
    relationships:
      parent: {targets: [workspace, folder], cardinality: one, required: false}
    inheritance:
      - relationship: parent
        permissions: [document.read]
`

func TestCompilePreservesAuthorizationSemantics(t *testing.T) {
	c, err := config.Parse([]byte(schema))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	if m.SchemaVersion != "1.1" {
		t.Fatalf("schema version = %q", m.SchemaVersion)
	}
	group := findType(t, m, "group")
	refs := group.Metadata.Relations["member"].DirectlyRelatedUserTypes
	if len(refs) != 2 || refs[1].Type != "group" || refs[1].Relation == nil || *refs[1].Relation != "member" {
		t.Fatalf("group member references = %#v", refs)
	}
	document := findType(t, m, "document")
	parentRefs := document.Metadata.Relations["parent"].DirectlyRelatedUserTypes
	if len(parentRefs) != 2 || parentRefs[0].Type != "folder" || parentRefs[1].Type != "workspace" {
		t.Fatalf("parent refs = %#v", parentRefs)
	}
	if _, ok := document.Relations["role_reader"]; !ok {
		t.Fatal("reader role relation absent")
	}
	read := document.Relations["permission_document_read"]
	if read.Union == nil || len(read.Union.Child) != 3 {
		t.Fatalf("document.read rewrite = %#v", read)
	}
	last := read.Union.Child[2].TupleToUserset
	if last == nil || last.Tupleset.Relation != "parent" || last.ComputedUserset.Relation != "permission_document_read" {
		t.Fatalf("inheritance rewrite = %#v", last)
	}
	// Parent types carry helper permission relations so tuple-to-userset is a
	// valid model construct even though document.read isn't publicly applicable.
	if _, ok := findType(t, m, "folder").Relations["permission_document_read"]; !ok {
		t.Fatal("folder inheritance helper absent")
	}
	audience := findType(t, m, "audience")
	if _, ok := audience.Relations["permission_api_invoke"]; !ok {
		t.Fatal("intrinsic audience permission absent")
	}
}

func TestCompileIsDeterministicAndJSONCompatible(t *testing.T) {
	c, _ := config.Parse([]byte(schema))
	a, _ := Compile(c)
	b, _ := Compile(c)
	ja, err := a.JSON()
	if err != nil {
		t.Fatal(err)
	}
	jb, _ := b.JSON()
	if !bytes.Equal(ja, jb) {
		t.Fatal("compiled JSON is not deterministic")
	}
	var decoded map[string]any
	if err := json.Unmarshal(ja, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["schema_version"] != "1.1" {
		t.Fatalf("JSON = %s", ja)
	}
}

func TestCompileRejectsNilAndInvalidConfig(t *testing.T) {
	if _, err := Compile(nil); err == nil {
		t.Fatal("expected nil error")
	}
	if _, err := Compile(&config.Config{Version: 1}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestRelationNames(t *testing.T) {
	if got := PermissionRelation("customer.billing.read"); got != "permission_customer_billing_read" {
		t.Fatalf("got %q", got)
	}
	if got := RoleRelation("support_agent"); got != "role_support_agent" {
		t.Fatalf("got %q", got)
	}
}

func findType(t *testing.T, m *Model, name string) TypeDefinition {
	t.Helper()
	for _, definition := range m.TypeDefinitions {
		if definition.Type == name {
			return definition
		}
	}
	t.Fatalf("type %q absent", name)
	return TypeDefinition{}
}
