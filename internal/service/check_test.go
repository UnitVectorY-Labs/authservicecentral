package service

import (
	"context"
	"reflect"
	"testing"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

type fakeEngine struct {
	checks  []EngineCheck
	answers []bool
}

func (*fakeEngine) WriteTuple(context.Context, database.AuthorizationTuple) error  { return nil }
func (*fakeEngine) DeleteTuple(context.Context, database.AuthorizationTuple) error { return nil }
func (f *fakeEngine) BatchCheck(_ context.Context, checks []EngineCheck) ([]bool, error) {
	f.checks = append([]EngineCheck(nil), checks...)
	return f.answers, nil
}

func TestBatchCheckDelegationAndOrdering(t *testing.T) {
	engine := &fakeEngine{answers: []bool{true, true, false, true}}
	s := &Service{config: testConfig(), engine: engine}
	checks := []PermissionCheck{
		{Permission: "document.read", Resource: database.ResourceRef{Type: "document", ID: "a"}},
		{Permission: "document.read", Resource: database.ResourceRef{Type: "document", ID: "b"}},
	}
	actor := database.PrincipalSubject("gcp", "service")
	results, err := s.BatchCheck(t.Context(), BatchCheckRequest{
		Subject: database.PrincipalSubject("corp", "alice"), Actor: &actor,
		Mode: database.DelegationIntersection, Checks: checks,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := []bool{results[0].Allowed, results[1].Allowed}; !reflect.DeepEqual(got, []bool{true, false}) {
		t.Fatalf("unexpected results %v", got)
	}
	if len(engine.checks) != 4 {
		t.Fatalf("got %d engine checks", len(engine.checks))
	}
	if engine.checks[0].Object != "document:YQ" || engine.checks[0].Subject != "principal:Y29ycA.YWxpY2U" {
		t.Fatalf("unexpected subject check %#v", engine.checks[0])
	}
	if engine.checks[1].Subject != "principal:Z2Nw.c2VydmljZQ" {
		t.Fatalf("unexpected actor check %#v", engine.checks[1])
	}
}
