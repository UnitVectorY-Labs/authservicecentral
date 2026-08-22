package service

import (
	"testing"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

func TestPrincipalEncodingIsUnambiguous(t *testing.T) {
	a, err := PrincipalObject("a:b", "c")
	if err != nil {
		t.Fatal(err)
	}
	b, err := PrincipalObject("a", "b:c")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("ambiguous encodings: %q", a)
	}
	if a != "principal:YTpi.Yw" {
		t.Fatalf("unexpected canonical encoding %q", a)
	}
}

func TestResourceAndUsersetEncoding(t *testing.T) {
	object, err := ResourceObject(database.ResourceRef{Type: "document", ID: "a:b/# c"})
	if err != nil {
		t.Fatal(err)
	}
	if object != "document:YTpiLyMgYw" {
		t.Fatalf("unexpected object %q", object)
	}
	userset, err := GroupUserset("a:b")
	if err != nil {
		t.Fatal(err)
	}
	if userset != "group:YTpi#member" {
		t.Fatalf("unexpected userset %q", userset)
	}
}

func TestTupleConstruction(t *testing.T) {
	tuple, err := relationshipTuple(database.ResourceRef{Type: "document", ID: "1"}, "parent", database.ResourceRef{Type: "folder", ID: "finance"})
	if err != nil {
		t.Fatal(err)
	}
	if tuple.Object != "document:MQ" || tuple.Relation != "parent" || tuple.Subject != "folder:ZmluYW5jZQ" {
		t.Fatalf("unexpected tuple %#v", tuple)
	}
	grant := database.Grant{Role: "editor", Resource: database.ResourceRef{Type: "document", ID: "1"}, Subject: database.PrincipalSubject("github", "alice")}
	tuple, err = grantTuple(grant)
	if err != nil {
		t.Fatal(err)
	}
	if tuple.Relation != "role_editor" || tuple.Subject != "principal:Z2l0aHVi.YWxpY2U" {
		t.Fatalf("unexpected grant tuple %#v", tuple)
	}
}
