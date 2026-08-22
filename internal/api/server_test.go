package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type fakeAuth struct{}

func (fakeAuth) Authenticate(_ context.Context, token string) (Identity, error) {
	if token == "bad" {
		return Identity{}, errors.New("bad")
	}
	if token == "limited" {
		return Identity{Subject: "corp:bob", Audience: "serviceauth-management"}, nil
	}
	if token == "custom" {
		return Identity{Subject: "corp:custom", Audience: "serviceauth-management", Permissions: []string{"custom.audiences.read"}}, nil
	}
	return Identity{Subject: "corp:alice", Audience: "serviceauth-management", Permissions: []string{"management.audiences.read", "management.audiences.write", "management.resources.read", "management.resources.write", "management.groups.read", "management.groups.write", "management.grants.read", "management.grants.write"}}, nil
}

type fakeBackend struct {
	called   string
	fail     error
	readyErr error
	exchange TokenExchangeRequest
	identity Identity
	check    CheckRequest
}

func (f *fakeBackend) mark(name string, id Identity) { f.called = name; f.identity = id }
func (f *fakeBackend) OAuthMetadata(context.Context) (OAuthMetadata, error) {
	f.called = "metadata"
	return OAuthMetadata{Issuer: "https://auth.test", TokenEndpoint: "https://auth.test/oauth2/token", JWKSURI: "https://auth.test/.well-known/jwks.json", GrantTypesSupported: []string{"exchange"}, SubjectTypes: []string{"public"}}, f.fail
}
func (f *fakeBackend) JWKS(context.Context) (map[string]any, error) {
	f.called = "jwks"
	return map[string]any{"keys": []any{}}, f.fail
}
func (f *fakeBackend) Exchange(_ context.Context, r TokenExchangeRequest) (TokenExchangeResponse, error) {
	f.called = "exchange"
	f.exchange = r
	return TokenExchangeResponse{AccessToken: "signed", IssuedTokenType: "access", TokenType: "Bearer", ExpiresIn: 60}, f.fail
}
func (f *fakeBackend) Ready(context.Context) error { return f.readyErr }
func (f *fakeBackend) CreateAudience(_ context.Context, i Identity, v Audience) (Audience, error) {
	f.mark("create-audience", i)
	return v, f.fail
}
func (f *fakeBackend) ListAudiences(_ context.Context, i Identity) ([]Audience, error) {
	f.mark("list-audiences", i)
	return []Audience{{ID: "a"}}, f.fail
}
func (f *fakeBackend) GetAudience(_ context.Context, i Identity, id string) (Audience, error) {
	f.mark("get-audience:"+id, i)
	return Audience{ID: id}, f.fail
}
func (f *fakeBackend) PatchAudience(_ context.Context, i Identity, id string, _ AudiencePatch) (Audience, error) {
	f.mark("patch-audience:"+id, i)
	return Audience{ID: id}, f.fail
}
func (f *fakeBackend) DeleteAudience(_ context.Context, i Identity, id string) error {
	f.mark("delete-audience:"+id, i)
	return f.fail
}
func (f *fakeBackend) CreateResource(_ context.Context, i Identity, v Resource) (Resource, error) {
	f.mark("create-resource", i)
	return v, f.fail
}
func (f *fakeBackend) GetResource(_ context.Context, i Identity, r ResourceRef) (Resource, error) {
	f.mark("get-resource:"+r.Type+":"+r.ID, i)
	return Resource{Type: r.Type, ID: r.ID}, f.fail
}
func (f *fakeBackend) PatchResource(_ context.Context, i Identity, r ResourceRef, _ ResourcePatch) (Resource, error) {
	f.mark("patch-resource:"+r.Type+":"+r.ID, i)
	return Resource{Type: r.Type, ID: r.ID}, f.fail
}
func (f *fakeBackend) DeleteResource(_ context.Context, i Identity, r ResourceRef) error {
	f.mark("delete-resource:"+r.Type+":"+r.ID, i)
	return f.fail
}
func (f *fakeBackend) PutRelationship(_ context.Context, i Identity, _ ResourceRef, rel string, _ RelationshipMutation) error {
	f.mark("put-relationship:"+rel, i)
	return f.fail
}
func (f *fakeBackend) DeleteRelationship(_ context.Context, i Identity, _ ResourceRef, rel string, _ RelationshipMutation) error {
	f.mark("delete-relationship:"+rel, i)
	return f.fail
}
func (f *fakeBackend) CreateGroup(_ context.Context, i Identity, v Group) (Group, error) {
	f.mark("create-group", i)
	return v, f.fail
}
func (f *fakeBackend) GetGroup(_ context.Context, i Identity, id string) (Group, error) {
	f.mark("get-group:"+id, i)
	return Group{ID: id}, f.fail
}
func (f *fakeBackend) DeleteGroup(_ context.Context, i Identity, id string) error {
	f.mark("delete-group:"+id, i)
	return f.fail
}
func (f *fakeBackend) AddMember(_ context.Context, i Identity, id string, _ MembershipRequest) error {
	f.mark("add-member:"+id, i)
	return f.fail
}
func (f *fakeBackend) DeleteMember(_ context.Context, i Identity, id string, _ MembershipRequest) error {
	f.mark("delete-member:"+id, i)
	return f.fail
}
func (f *fakeBackend) CreateGrant(_ context.Context, i Identity, v Grant) (Grant, error) {
	f.mark("create-grant", i)
	v.ID = "g"
	return v, f.fail
}
func (f *fakeBackend) DeleteGrant(_ context.Context, i Identity, id string) error {
	f.mark("delete-grant:"+id, i)
	return f.fail
}
func (f *fakeBackend) ListGrants(_ context.Context, i Identity) ([]Grant, error) {
	f.mark("list-grants", i)
	return []Grant{}, f.fail
}
func (f *fakeBackend) Check(_ context.Context, i Identity, r CheckRequest) (CheckResponse, error) {
	f.mark("check", i)
	f.check = r
	return CheckResponse{Results: []CheckResult{{ID: r.Checks[0].ID, Allowed: false}}}, f.fail
}

func newTestServer(t *testing.T, b *fakeBackend, options Options) *Server {
	t.Helper()
	s, err := New(b, fakeAuth{}, options)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func perform(s http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestPublicEndpointsAndTokenExchange(t *testing.T) {
	b := &fakeBackend{}
	s := newTestServer(t, b, Options{})
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/jwks.json", "/health/live", "/health/ready"} {
		w := perform(s, "GET", path, "", "")
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if w.Header().Get("X-Request-ID") == "" {
			t.Errorf("%s missing request id", path)
		}
	}
	form := url.Values{"grant_type": {"exchange"}, "subject_token": {"external-secret-token"}, "subject_token_type": {"jwt"}, "audience": {"docs"}}.Encode()
	r := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK || b.exchange.SubjectToken != "external-secret-token" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("exchange: %d %#v %s", w.Code, b.exchange, w.Body.String())
	}
	w = perform(s, "POST", "/oauth2/token", `{}`, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("JSON token exchange accepted: %d", w.Code)
	}
	b.readyErr = errors.New("database down")
	w = perform(s, "GET", "/health/ready", "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness: %d", w.Code)
	}
}

func TestSwaggerUIIsOptionalAndServesTheEmbeddedContract(t *testing.T) {
	without := newTestServer(t, &fakeBackend{}, Options{})
	w := perform(without, http.MethodGet, "/", "", "")
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "SwaggerUIBundle") {
		t.Fatalf("Swagger UI should be disabled by default in transport options: %d %s", w.Code, w.Body.String())
	}

	with := newTestServer(t, &fakeBackend{}, Options{SwaggerUI: true, OpenAPISpec: []byte("openapi: 3.1.0\ninfo:\n  title: test\n")})
	w = perform(with, http.MethodGet, "/", "", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "SwaggerUIBundle") || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("Swagger UI: %d %s", w.Code, w.Body.String())
	}
	w = perform(with, http.MethodGet, "/openapi.yaml", "", "")
	if w.Code != http.StatusOK || w.Body.String() != "openapi: 3.1.0\ninfo:\n  title: test\n" || w.Header().Get("Content-Type") != "application/yaml; charset=utf-8" {
		t.Fatalf("OpenAPI document: %d %q", w.Code, w.Body.String())
	}
	w = perform(with, http.MethodGet, "/swagger-ui/swagger-ui.css", "", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("embedded Swagger asset: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestAuthenticationPermissionAndStructuredErrors(t *testing.T) {
	b := &fakeBackend{}
	s := newTestServer(t, b, Options{})
	w := perform(s, "POST", "/v1/check", `{"checks":[{"id":"x","permission":"document.read","resource":{"type":"document","id":"1"}}]}`, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer: %d", w.Code)
	}
	w = perform(s, "POST", "/v1/check", `{"checks":[{"id":"x","permission":"document.read","resource":{"type":"document","id":"1"}}]}`, "bad")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid bearer: %d", w.Code)
	}
	w = perform(s, "GET", "/v1/manage/audiences", "", "limited")
	if w.Code != http.StatusForbidden {
		t.Fatalf("management permission: %d", w.Code)
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || envelope.Error.Code != "insufficient_permission" || envelope.Error.RequestID == "" {
		t.Fatalf("bad error envelope: %s", w.Body.String())
	}
	b.fail = ErrNotFound
	w = perform(s, "GET", "/v1/manage/audiences/missing", "", "good")
	if w.Code != http.StatusNotFound {
		t.Fatalf("not found: %d", w.Code)
	}
}

func TestManagementPermissionCanBeConfiguredPerRouteFamily(t *testing.T) {
	b := &fakeBackend{}
	s := newTestServer(t, b, Options{ManagementPermissions: map[string]string{"audiences.read": "custom.audiences.read"}})
	w := perform(s, http.MethodGet, "/v1/manage/audiences", "", "custom")
	if w.Code != http.StatusOK || b.called != "list-audiences" {
		t.Fatalf("configured management permission: %d %q %s", w.Code, b.called, w.Body.String())
	}
	w = perform(s, http.MethodGet, "/v1/manage/audiences", "", "good")
	if w.Code != http.StatusForbidden {
		t.Fatalf("default permission should not satisfy configured permission: %d %s", w.Code, w.Body.String())
	}
}

func TestBatchChecksUseAuthenticatedIdentityAndReturnFalseAs200(t *testing.T) {
	b := &fakeBackend{}
	s := newTestServer(t, b, Options{MaxBatchSize: 2, Metrics: true})
	body := `{"checks":[{"id":"x","permission":"document.read","resource":{"type":"document","id":"1"}}]}`
	w := perform(s, "POST", "/v1/check", body, "good")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"allowed":false`) {
		t.Fatalf("denial semantics: %d %s", w.Code, w.Body.String())
	}
	if b.identity.Subject != "corp:alice" || b.called != "check" {
		t.Fatalf("identity not obtained from token: %#v", b.identity)
	}
	w = perform(s, "POST", "/v1/check", `{"checks":[]}`, "good")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty batch: %d", w.Code)
	}
	w = perform(s, "POST", "/v1/check", `{"checks":[{"id":"1","permission":"p","resource":{"type":"t","id":"1"}},{"id":"2","permission":"p","resource":{"type":"t","id":"2"}},{"id":"3","permission":"p","resource":{"type":"t","id":"3"}}]}`, "good")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized batch: %d", w.Code)
	}
	w = perform(s, "GET", "/metrics", "", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "serviceauth_authorization_denied_total 1") {
		t.Fatalf("metrics: %s", w.Body.String())
	}
}

func TestManagementRouteFamilies(t *testing.T) {
	b := &fakeBackend{}
	s := newTestServer(t, b, Options{})
	tests := []struct {
		method, path, body string
		status             int
		called             string
	}{
		{"POST", "/v1/manage/audiences", `{"id":"docs","token_ttl_seconds":60,"delegation":{"enabled":false,"mode":"disabled"}}`, 201, "create-audience"}, {"GET", "/v1/manage/audiences", "", 200, "list-audiences"}, {"GET", "/v1/manage/audiences/docs", "", 200, "get-audience:docs"}, {"PATCH", "/v1/manage/audiences/docs", `{"display_name":"Docs"}`, 200, "patch-audience:docs"}, {"DELETE", "/v1/manage/audiences/docs", "", 204, "delete-audience:docs"},
		{"POST", "/v1/manage/resources", `{"type":"document","id":"1","relationships":{"parent":{"type":"folder","id":"f"}}}`, 201, "create-resource"}, {"GET", "/v1/manage/resources/document/1", "", 200, "get-resource:document:1"}, {"PATCH", "/v1/manage/resources/document/1", `{"metadata":{"x":true}}`, 200, "patch-resource:document:1"}, {"DELETE", "/v1/manage/resources/document/1", "", 204, "delete-resource:document:1"}, {"PUT", "/v1/manage/resources/document/1/relationships/parent", `{"target":{"type":"folder","id":"f"}}`, 204, "put-relationship:parent"}, {"DELETE", "/v1/manage/resources/document/1/relationships/parent", "", 204, "delete-relationship:parent"},
		{"POST", "/v1/manage/groups", `{"id":"eng"}`, 201, "create-group"}, {"GET", "/v1/manage/groups/eng", "", 200, "get-group:eng"}, {"DELETE", "/v1/manage/groups/eng", "", 204, "delete-group:eng"}, {"POST", "/v1/manage/groups/eng/members", `{"member":{"type":"principal","source":"corp","subject":"alice"}}`, 204, "add-member:eng"}, {"DELETE", "/v1/manage/groups/eng/members", `{"member":{"type":"principal","source":"corp","subject":"alice"}}`, 204, "delete-member:eng"},
		{"POST", "/v1/manage/grants", `{"subject":{"type":"principal","source":"corp","subject":"alice"},"role":"reader","resource":{"type":"document","id":"1"}}`, 201, "create-grant"}, {"GET", "/v1/manage/grants", "", 200, "list-grants"}, {"DELETE", "/v1/manage/grants/g", "", 204, "delete-grant:g"},
	}
	for _, tt := range tests {
		b.called = ""
		w := perform(s, tt.method, tt.path, tt.body, "good")
		if w.Code != tt.status || b.called != tt.called {
			t.Errorf("%s %s: status=%d called=%q body=%s", tt.method, tt.path, w.Code, b.called, w.Body.String())
		}
	}
}

func TestBodyLimitsUnknownFieldsAndInsecureDevelopmentManagement(t *testing.T) {
	b := &fakeBackend{}
	s := newTestServer(t, b, Options{MaxBodyBytes: 64, InsecureManagement: true})
	w := perform(s, "GET", "/v1/manage/audiences", "", "")
	if w.Code != http.StatusOK || b.identity.Subject != "development-insecure-management" {
		t.Fatalf("insecure development option: %d %#v", w.Code, b.identity)
	}
	w = perform(s, "POST", "/v1/manage/resources", `{"type":"document","id":"1","unknown":true}`, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", w.Code)
	}
	w = perform(s, "POST", "/v1/manage/resources", `{"type":"document","id":"`+strings.Repeat("x", 100)+`"}`, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: %d", w.Code)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(nil, fakeAuth{}, Options{}); err == nil {
		t.Fatal("nil backend accepted")
	}
	if _, err := New(&fakeBackend{}, nil, Options{}); err == nil {
		t.Fatal("nil authenticator accepted")
	}
}

func TestUnknownRouteHasStructuredError(t *testing.T) {
	s := newTestServer(t, &fakeBackend{}, Options{})
	w := perform(s, "GET", "/does-not-exist", "", "")
	if w.Code != http.StatusNotFound || w.Header().Get("Content-Type") != "application/json" || !strings.Contains(w.Body.String(), `"request_id"`) {
		t.Fatalf("unknown route response: %d %s", w.Code, w.Body.String())
	}
}
