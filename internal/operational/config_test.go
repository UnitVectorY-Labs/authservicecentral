package operational

import "testing"

func TestParseFlagOverridesEnvironment(t *testing.T) {
	t.Setenv("SERVICEAUTH_CONFIG", "env.yaml")
	t.Setenv("SERVICEAUTH_MAX_BATCH_SIZE", "20")
	c, err := Parse("validate", []string{"--config", "flag.yaml", "--max-batch-size", "30"})
	if err != nil {
		t.Fatal(err)
	}
	if c.ConfigPath != "flag.yaml" || c.MaxBatchSize != 30 {
		t.Fatalf("unexpected config: %#v", c)
	}
}

func TestSwaggerUICanBeToggledByEnvironmentAndFlag(t *testing.T) {
	t.Setenv("SERVICEAUTH_SWAGGER_UI", "false")
	c, err := Parse("validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.SwaggerUI {
		t.Fatal("Swagger UI environment toggle was ignored")
	}
	c, err = Parse("validate", []string{"--swagger-ui=true"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.SwaggerUI {
		t.Fatal("Swagger UI flag was ignored")
	}
}

func TestParseRejectsInvalidBatch(t *testing.T) {
	if _, err := Parse("run", []string{"--max-batch-size", "0"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseRejectsInvalidRuntimeDurations(t *testing.T) {
	if _, err := Parse("run", []string{"--shutdown-timeout=0s"}); err == nil {
		t.Fatal("expected shutdown timeout error")
	}
	if _, err := Parse("run", []string{"--reconcile-interval=-1s"}); err == nil {
		t.Fatal("expected reconcile interval error")
	}
	if _, err := Parse("run", []string{"--reconcile-batch=1001"}); err == nil {
		t.Fatal("expected reconcile batch error")
	}
}

func TestParseBootstrapDefaultsAndRequirements(t *testing.T) {
	if _, err := Parse("bootstrap", nil); err == nil {
		t.Fatal("expected required bootstrap principal flags")
	}
	c, err := Parse("bootstrap", []string{"--source=corp", "--subject=alice", "--role=admin"})
	if err != nil {
		t.Fatal(err)
	}
	if c.ManagementAudience != "serviceauth-management" || c.ManagementTTL != 900 {
		t.Fatalf("unexpected bootstrap defaults %#v", c)
	}
}
