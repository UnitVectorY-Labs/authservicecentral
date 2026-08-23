package integration

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/api"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/app"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/authn"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/authorization/compiler"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/cmd"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
	engine "github.com/UnitVectorY-Labs/authservicecentral/internal/openfga"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/operational"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/service"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/token"
)

func TestPostgresEndToEnd(t *testing.T) {
	adminURL := os.Getenv("SERVICEAUTH_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("SERVICEAUTH_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	databaseURL := createTestDatabase(t, ctx, adminURL)
	externalKey := mustRSA(t)
	platformKey := mustRSA(t)
	externalPublic := publicPEM(t, &externalKey.PublicKey)
	platformFile := filepath.Join(t.TempDir(), "platform-key.pem")
	if err := os.WriteFile(platformFile, privatePEM(t, platformKey), 0o600); err != nil {
		t.Fatal(err)
	}
	schema := testSchema(externalPublic)
	cfg, err := config.Parse([]byte(schema))
	if err != nil {
		t.Fatal(err)
	}
	api.SetOpenAPISpec([]byte("openapi: 3.1.0\ninfo:\n  title: integration test\n"))

	t.Run("migrations and model activation", func(t *testing.T) { activate(t, ctx, databaseURL, cfg) })
	t.Run("controlled management bootstrap", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "serviceauth.yaml")
		if err := os.WriteFile(path, []byte(schema), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Bootstrap([]string{"--config", path, "--database-url", databaseURL, "--source", "test", "--subject", "alice", "--role", "serviceauth_admin"}); err != nil {
			t.Fatal(err)
		}
	})
	op := operational.Config{DatabaseURL: databaseURL, Issuer: "https://platform.test", SigningProvider: "local", SigningKeyFile: platformFile, ManagementOpen: true, SwaggerUI: true, MaxBatchSize: 100, HTTPTimeout: 5 * time.Second, ReconcileInterval: time.Hour, ReconcileBatch: 100, Metrics: true}
	runtime, err := app.BuildRuntime(ctx, op, cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(runtime.Handler)
	client := server.Client()
	closeRuntime := func() {
		server.Close()
		if err := runtime.Close(); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	}

	t.Run("health metadata and JWKS", func(t *testing.T) {
		for _, path := range []string{"/health/live", "/health/ready", "/metrics"} {
			status, body := request(t, client, http.MethodGet, server.URL+path, "", nil, "")
			if status != 200 {
				t.Fatalf("%s: %d %s", path, status, body)
			}
		}
		for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
			status, body := request(t, client, http.MethodGet, server.URL+path, "", nil, "")
			if status != 200 || !strings.Contains(body, `"issuer":"https://platform.test"`) || !strings.Contains(body, token.GrantTypeTokenExchange) {
				t.Fatalf("metadata %s: %d %s", path, status, body)
			}
		}
		status, body := request(t, client, http.MethodGet, server.URL+"/.well-known/jwks.json", "", nil, "")
		if status != 200 || !strings.Contains(body, `"kty":"RSA"`) || !strings.Contains(body, `"kid":`) {
			t.Fatalf("JWKS: %d %s", status, body)
		}
		status, body = request(t, client, http.MethodGet, server.URL+"/", "", nil, "")
		if status != http.StatusOK || !strings.Contains(body, "SwaggerUIBundle") {
			t.Fatalf("Swagger UI: %d %s", status, body)
		}
		status, body = request(t, client, http.MethodGet, server.URL+"/openapi.yaml", "", nil, "")
		if status != http.StatusOK || !strings.Contains(body, "integration test") {
			t.Fatalf("OpenAPI document: %d %s", status, body)
		}
	})

	post := func(path, body string) string {
		status, response := request(t, client, http.MethodPost, server.URL+path, "application/json", strings.NewReader(body), "")
		if status != http.StatusCreated && status != http.StatusNoContent {
			t.Fatalf("POST %s: %d %s", path, status, response)
		}
		return response
	}
	post("/v1/manage/audiences", `{"id":"docs","display_name":"Documents","token_ttl_seconds":600,"delegation":{"enabled":false,"mode":"disabled"}}`)
	post("/v1/manage/resources", `{"type":"folder","id":"finance"}`)
	post("/v1/manage/resources", `{"type":"folder","id":"legal"}`)
	post("/v1/manage/resources", `{"type":"document","id":"report","relationships":{"parent":{"type":"folder","id":"finance"}}}`)
	post("/v1/manage/groups", `{"id":"inner"}`)
	post("/v1/manage/groups", `{"id":"outer"}`)
	post("/v1/manage/groups/inner/members", `{"member":{"type":"principal","source":"test","subject":"alice"}}`)
	post("/v1/manage/groups/outer/members", `{"member":{"type":"group","group":"inner"}}`)
	post("/v1/manage/grants", `{"id":"g-folder","subject":{"type":"group","group":"outer"},"role":"reader","resource":{"type":"folder","id":"finance"}}`)
	post("/v1/manage/grants", `{"id":"g-doc-bob","subject":{"type":"principal","source":"test","subject":"bob"},"role":"editor","resource":{"type":"document","id":"report"}}`)
	post("/v1/manage/grants", `{"id":"g-aud-alice","subject":{"type":"principal","source":"test","subject":"alice"},"role":"reader","resource":{"type":"audience","id":"docs"}}`)
	post("/v1/manage/grants", `{"id":"g-aud-bob","subject":{"type":"principal","source":"test","subject":"bob"},"role":"editor","resource":{"type":"audience","id":"docs"}}`)
	drain(t, ctx, runtime)

	var pending int
	if err := connector(t, databaseURL).QueryRowContext(ctx, `SELECT count(*) FROM platform.authorization_operations WHERE state <> 'completed'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("outbox has %d incomplete operations", pending)
	}
	aliceExternal := externalJWT(t, externalKey, "alice")
	bobExternal := externalJWT(t, externalKey, "bob")
	aliceToken := exchange(t, client, server.URL, aliceExternal, "", http.StatusOK)
	_, claims, _, _, err := authn.DecodeCompact(aliceToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims["email"] != "alice@example.com" || claims["aud"] != "docs" {
		t.Fatalf("platform claims=%#v", claims)
	}
	permissions := stringSlice(claims["permissions"])
	if !contains(permissions, "api.invoke") {
		t.Fatalf("permissions=%v", permissions)
	}

	t.Run("inherited allow denial and validation", func(t *testing.T) {
		check(t, client, server.URL, aliceToken, "document.read", "document", "report", http.StatusOK, true)
		check(t, client, server.URL, aliceToken, "document.write", "document", "report", http.StatusOK, false)
		check(t, client, server.URL, aliceToken, "missing.permission", "document", "report", http.StatusBadRequest, false)
		check(t, client, server.URL, aliceToken, "document.read", "folder", "finance", http.StatusBadRequest, false)
		check(t, client, server.URL, aliceToken, "document.read", "unknown", "report", http.StatusBadRequest, false)
	})

	t.Run("move revokes inherited access", func(t *testing.T) {
		status, body := request(t, client, http.MethodPut, server.URL+"/v1/manage/resources/document/report/relationships/parent", "application/json", strings.NewReader(`{"target":{"type":"folder","id":"legal"}}`), "")
		if status != 204 {
			t.Fatalf("move: %d %s", status, body)
		}
		drain(t, ctx, runtime)
		check(t, client, server.URL, aliceToken, "document.read", "document", "report", 200, false)
		status, body = request(t, client, http.MethodPut, server.URL+"/v1/manage/resources/document/report/relationships/parent", "application/json", strings.NewReader(`{"target":{"type":"folder","id":"finance"}}`), "")
		if status != 204 {
			t.Fatalf("move back: %d %s", status, body)
		}
		drain(t, ctx, runtime)
	})

	t.Run("implicit resource creation", func(t *testing.T) {
		post("/v1/manage/grants", `{"id":"g-implicit","subject":{"type":"principal","source":"test","subject":"alice"},"role":"reader","resource":{"type":"document","id":"implicit"},"create_resource_if_missing":true}`)
		drain(t, ctx, runtime)
		status, _ := request(t, client, "GET", server.URL+"/v1/manage/resources/document/implicit", "", nil, "")
		if status != 200 {
			t.Fatalf("implicit resource status=%d", status)
		}
		check(t, client, server.URL, aliceToken, "document.read", "document", "implicit", 200, true)
	})

	t.Run("delegation modes", func(t *testing.T) {
		expected := map[string][]string{"subject": {"api.invoke"}, "actor": {"api.admin"}, "intersection": {}, "union": {"api.admin", "api.invoke"}}
		for mode, want := range expected {
			patchAudienceMode(t, client, server.URL, mode)
			delegated := exchange(t, client, server.URL, aliceExternal, bobExternal, 200)
			_, raw, _, _, _ := authn.DecodeCompact(delegated)
			got := stringSlice(raw["permissions"])
			for _, permission := range want {
				if !contains(got, permission) {
					t.Fatalf("mode %s permissions=%v", mode, got)
				}
			}
			if raw["act"] == nil {
				t.Fatalf("mode %s missing act", mode)
			}
			fineWant := mode == "subject" || mode == "union"
			check(t, client, server.URL, delegated, "document.read", "document", "report", 200, fineWant)
		}
		patchAudienceMode(t, client, server.URL, "disabled")
		exchange(t, client, server.URL, aliceExternal, bobExternal, http.StatusBadRequest)
	})

	t.Run("resource deletion cleanup", func(t *testing.T) {
		status, body := request(t, client, http.MethodDelete, server.URL+"/v1/manage/resources/folder/finance", "", nil, "")
		if status != 204 {
			t.Fatalf("delete: %d %s", status, body)
		}
		drain(t, ctx, runtime)
		object, _ := service.ResourceObject(database.ResourceRef{Type: "folder", ID: "finance"})
		refs, err := runtime.Engine.TuplesReferencingObject(ctx, object)
		if err != nil || len(refs) != 0 {
			t.Fatalf("OpenFGA references=%#v err=%v", refs, err)
		}
		check(t, client, server.URL, aliceToken, "document.read", "document", "report", 200, false)
	})

	bobToken := exchange(t, client, server.URL, bobExternal, "", http.StatusOK)
	closeRuntime()

	t.Run("persistence restart", func(t *testing.T) {
		runtime, err = app.BuildRuntime(ctx, op, cfg)
		if err != nil {
			t.Fatal(err)
		}
		server = httptest.NewServer(runtime.Handler)
		client = server.Client()
		check(t, client, server.URL, bobToken, "document.write", "document", "report", 200, true)
	})

	schemaV2 := strings.Replace(schema, "  document.write: {resources: [document]}", "  document.write: {resources: [document]}\n  document.comment: {resources: [document]}", 1)
	schemaV2 = strings.Replace(schemaV2, "permissions: [api.admin, document.write]", "permissions: [api.admin, document.write, document.comment]", 1)
	cfgV2, err := config.Parse([]byte(schemaV2))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("fingerprint mismatch fails closed", func(t *testing.T) {
		if candidate, err := app.BuildRuntime(ctx, op, cfgV2); err == nil {
			candidate.Close()
			t.Fatal("mismatched configuration started")
		}
	})
	server.Close()
	runtime.Close()
	t.Run("model evolution preserves tuples", func(t *testing.T) {
		activate(t, ctx, databaseURL, cfgV2)
		runtime, err = app.BuildRuntime(ctx, op, cfgV2)
		if err != nil {
			t.Fatal(err)
		}
		server = httptest.NewServer(runtime.Handler)
		client = server.Client()
		defer server.Close()
		defer runtime.Close()
		check(t, client, server.URL, bobToken, "document.comment", "document", "report", 200, true)
	})
}

func activate(t *testing.T, ctx context.Context, databaseURL string, cfg *config.Config) {
	t.Helper()
	store, err := app.OpenDatabase(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engine.MigratePostgres(engine.PostgresConfig{URI: databaseURL}); err != nil {
		t.Fatal(err)
	}
	fga, err := engine.NewPostgres(ctx, engine.PostgresConfig{URI: databaseURL, Activations: app.ActivationStore{DB: store}})
	if err != nil {
		t.Fatal(err)
	}
	defer fga.Close()
	model, err := compiler.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := cfg.Fingerprint()
	if _, _, err := fga.EnsureModel(ctx, fingerprint, model); err != nil {
		t.Fatal(err)
	}
}

func drain(t *testing.T, ctx context.Context, runtime *app.Runtime) {
	t.Helper()
	for i := 0; i < 20; i++ {
		n, err := runtime.Service.Reconcile(ctx, service.Mutation{OperationID: fmt.Sprintf("integration-drain-%d-%d", time.Now().UnixNano(), i)}, 100)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
	}
	t.Fatal("outbox did not drain")
}

func request(t *testing.T, client *http.Client, method, target, contentType string, body io.Reader, bearer string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func exchange(t *testing.T, client *http.Client, base, subject, actor string, wantStatus int) string {
	t.Helper()
	form := url.Values{"grant_type": {token.GrantTypeTokenExchange}, "subject_token": {subject}, "subject_token_type": {token.TokenTypeJWT}, "audience": {"docs"}}
	if actor != "" {
		form.Set("actor_token", actor)
		form.Set("actor_token_type", token.TokenTypeJWT)
	}
	status, body := request(t, client, "POST", base+"/oauth2/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()), "")
	if status != wantStatus {
		t.Fatalf("exchange: %d %s", status, body)
	}
	if status != 200 {
		return ""
	}
	var response struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &response); err != nil || response.AccessToken == "" {
		t.Fatalf("exchange response: %v %s", err, body)
	}
	return response.AccessToken
}

func check(t *testing.T, client *http.Client, base, bearer, permission, resourceType, id string, wantStatus int, wantAllowed bool) {
	t.Helper()
	body := fmt.Sprintf(`{"checks":[{"id":"check","permission":%q,"resource":{"type":%q,"id":%q}}]}`, permission, resourceType, id)
	status, response := request(t, client, "POST", base+"/v1/check", "application/json", strings.NewReader(body), bearer)
	if status != wantStatus {
		t.Fatalf("check %s: %d %s", permission, status, response)
	}
	if status == 200 {
		var result struct {
			Results []struct {
				Allowed bool `json:"allowed"`
			} `json:"results"`
		}
		if err := json.Unmarshal([]byte(response), &result); err != nil || len(result.Results) != 1 || result.Results[0].Allowed != wantAllowed {
			t.Fatalf("check response: %v %s", err, response)
		}
	}
}

func patchAudienceMode(t *testing.T, client *http.Client, base, mode string) {
	t.Helper()
	enabled := mode != "disabled"
	body := fmt.Sprintf(`{"delegation":{"enabled":%t,"mode":%q}}`, enabled, mode)
	status, response := request(t, client, "PATCH", base+"/v1/manage/audiences/docs", "application/json", strings.NewReader(body), "")
	if status != 200 {
		t.Fatalf("patch delegation: %d %s", status, response)
	}
}

func testSchema(public string) string {
	return fmt.Sprintf(`version: 1
token_sources:
  test:
    issuer: https://external.test
    keys:
      public_key: |
%s
    algorithms: [RS256]
    identity: {subject_claim: sub, prefix: test}
    validation:
      audience: {any_of: [auth-exchange]}
      claims:
        tenant: {equals: acme}
    propagate_claims:
      email: {from: email}
permissions:
  management.audiences.write: {resources: [audience]}
  api.invoke: {resources: [audience]}
  api.admin: {resources: [audience]}
  folder.read: {resources: [folder]}
  document.read: {resources: [document]}
  document.write: {resources: [document]}
roles:
  serviceauth_admin: {permissions: [management.audiences.write]}
  reader: {permissions: [api.invoke, folder.read, document.read]}
  editor: {permissions: [api.admin, document.write]}
resources:
  folder: {relationships: {}}
  document:
    relationships:
      parent: {targets: [folder], cardinality: one, required: false}
    inheritance:
      - relationship: parent
        permissions: [document.read]
`, indent(public, 8))
}

func externalJWT(t *testing.T, key *rsa.PrivateKey, subject string) string {
	t.Helper()
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	sum := sha256.Sum256(der)
	kid := base64.RawURLEncoding.EncodeToString(sum[:])
	now := time.Now()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	claims := map[string]any{"iss": "https://external.test", "sub": subject, "aud": "auth-exchange", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "tenant": "acme", "email": subject + "@example.com"}
	encoded := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	input := encoded(header) + "." + encoded(claims)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func publicPEM(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
func privatePEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
func indent(value string, n int) string {
	prefix := strings.Repeat(" ", n)
	return prefix + strings.ReplaceAll(strings.TrimSuffix(value, "\n"), "\n", "\n"+prefix)
}
func stringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func createTestDatabase(t *testing.T, ctx context.Context, adminURL string) string {
	t.Helper()
	parsed, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("serviceauth_e2e_%d", time.Now().UnixNano())
	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		admin.Close()
		t.Fatalf("create test database: %v", err)
	}
	parsed.Path = "/" + name
	parsed.RawPath = ""
	testURL := parsed.String()
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = admin.ExecContext(cleanupCtx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()`, name)
		if _, err := admin.ExecContext(cleanupCtx, `DROP DATABASE IF EXISTS "`+name+`"`); err != nil {
			t.Errorf("drop test database: %v", err)
		}
		admin.Close()
	})
	return testURL
}

// connector keeps the integration query on the same pgx database/sql driver.
func connector(t *testing.T, databaseURL string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
