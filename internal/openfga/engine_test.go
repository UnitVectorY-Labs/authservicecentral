package openfga

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/openfga/openfga/pkg/storage/memory"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/authorization/compiler"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
)

const testSchema = `version: 1
permissions:
  document.read: {resources: [document]}
  document.write: {resources: [document]}
  folder.read: {resources: [folder]}
roles:
  reader: {permissions: [document.read, folder.read]}
  editor: {permissions: [document.read, document.write]}
resources:
  folder: {relationships: {}}
  document:
    relationships:
      parent: {targets: [folder], cardinality: one, required: false}
    inheritance:
      - relationship: parent
        permissions: [document.read]
`

func newTestEngine(t *testing.T) (*Engine, *compiler.Model, string) {
	t.Helper()
	ctx := context.Background()
	cfg, err := config.Parse([]byte(testSchema))
	if err != nil {
		t.Fatal(err)
	}
	model, err := compiler.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := cfg.Fingerprint()
	engine, err := New(ctx, Options{Datastore: memory.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return engine, model, fingerprint
}

func TestModelLifecycleAndStoreReuse(t *testing.T) {
	ctx := context.Background()
	ds := memory.New()
	activations := NewMemoryActivationStore()
	first, err := New(ctx, Options{Datastore: ds, StoreName: "one", Activations: activations})
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(ctx, Options{Datastore: ds, StoreName: "one", Activations: activations})
	if err != nil {
		t.Fatal(err)
	}
	if first.StoreID() != second.StoreID() {
		t.Fatalf("stores differ: %s %s", first.StoreID(), second.StoreID())
	}
	first.server.Close()
	second.server.Close()
	ds.Close()
}

func TestActivateVerifyEnsure(t *testing.T) {
	ctx := context.Background()
	e, model, fingerprint := newTestEngine(t)
	activation, err := e.ActivateModel(ctx, fingerprint, model)
	if err != nil {
		t.Fatal(err)
	}
	if activation.ModelID == "" {
		t.Fatal("empty model ID")
	}
	if _, err := e.VerifyFingerprint(ctx, fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := e.VerifyFingerprint(ctx, "different"); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("error=%v", err)
	}
	same, written, err := e.EnsureModel(ctx, fingerprint, model)
	if err != nil || written || same.ModelID != activation.ModelID {
		t.Fatalf("ensure=%#v written=%v err=%v", same, written, err)
	}
}

func TestGroupInheritanceBatchCheckAndCleanup(t *testing.T) {
	ctx := context.Background()
	e, model, fingerprint := newTestEngine(t)
	if _, err := e.ActivateModel(ctx, fingerprint, model); err != nil {
		t.Fatal(err)
	}
	tuples := []Tuple{{"group:backend", "member", "principal:github_alice"}, {"folder:finance", "role_reader", "group:backend#member"}, {"document:report", "parent", "folder:finance"}, {"document:report", "role_editor", "principal:github_bob"}}
	if err := e.WriteTuples(ctx, tuples); err != nil {
		t.Fatal(err)
	}
	if err := e.WriteTuples(ctx, tuples); err != nil {
		t.Fatalf("idempotent write: %v", err)
	}
	results, err := e.BatchCheck(ctx, []Check{{"principal:github_alice", "permission_document_read", "document:report"}, {"principal:github_alice", "permission_document_write", "document:report"}, {"principal:github_bob", "permission_document_write", "document:report"}})
	if err != nil {
		t.Fatal(err)
	}
	if !results[0].Allowed || results[1].Allowed || !results[2].Allowed {
		t.Fatalf("results=%#v", results)
	}
	refs, err := e.TuplesReferencingObject(ctx, "folder:finance")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("references=%#v", refs)
	}
	if err := e.DeleteObjectTuples(ctx, "folder:finance"); err != nil {
		t.Fatal(err)
	}
	refs, err = e.TuplesReferencingObject(ctx, "folder:finance")
	if err != nil || len(refs) != 0 {
		t.Fatalf("remaining=%#v err=%v", refs, err)
	}
	results, err = e.BatchCheck(ctx, []Check{{"principal:github_alice", "permission_document_read", "document:report"}})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Allowed {
		t.Fatal("deleted parent still grants access")
	}
}

func TestPostgresIntegration(t *testing.T) {
	uri := os.Getenv("OPENFGA_TEST_POSTGRES_URI")
	if uri == "" {
		t.Skip("OPENFGA_TEST_POSTGRES_URI is not set")
	}
	cfg := PostgresConfig{URI: uri, StoreName: "authservicecentral-integration"}
	if err := MigratePostgres(cfg); err != nil {
		t.Fatal(err)
	}
	engine, err := NewPostgres(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine.Close()
}
