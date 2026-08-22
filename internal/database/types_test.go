package database

import "testing"

func TestPersistenceHelpers(t *testing.T) {
	if got := string(jsonOrObject(nil)); got != "{}" {
		t.Fatalf("jsonOrObject(nil) = %q", got)
	}
	if got := limitOrDefault(0); got != 100 {
		t.Fatalf("limitOrDefault(0) = %d", got)
	}
	if got := limitOrDefault(1001); got != 100 {
		t.Fatalf("limitOrDefault(1001) = %d", got)
	}
	if got := limitOrDefault(25); got != 25 {
		t.Fatalf("limitOrDefault(25) = %d", got)
	}
	p := PrincipalSubject("github", "alice")
	if p.Kind != "principal" || p.Source != "github" || p.Principal != "alice" {
		t.Fatalf("unexpected principal subject: %#v", p)
	}
	g := GroupSubject("engineering")
	if g.Kind != "group" || g.GroupID != "engineering" {
		t.Fatalf("unexpected group subject: %#v", g)
	}
}

func TestEnqueueRejectsIncompleteTupleBeforeDatabaseAccess(t *testing.T) {
	err := enqueueTuple(t.Context(), nil, TupleOperation{OperationID: "request-1", Action: "write"})
	if err == nil {
		t.Fatal("expected validation error")
	}
}
