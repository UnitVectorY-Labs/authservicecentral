package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCTLDocumentedCommands(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		method, path string
		body         any
		form         url.Values
	}{
		{"token exchange", []string{"token", "exchange", "--subject-token", "external.jwt", "--audience", "docs"}, "POST", "/oauth2/token", nil, url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {"external.jwt"}, "subject_token_type": {jwtTokenType}, "audience": {"docs"}}},
		{"check", []string{"check", "--permission", "document.read", "--resource-type", "document", "--resource-id", "one"}, "POST", "/v1/check", apiJSON(`{"checks":[{"id":"check-1","permission":"document.read","resource":{"type":"document","id":"one"}}]}`), nil},
		{"audiences create", []string{"audiences", "create", "--id", "docs", "--display-name", "Docs", "--token-ttl", "15m", "--delegation-mode", "subject"}, "POST", "/v1/manage/audiences", apiJSON(`{"id":"docs","display_name":"Docs","token_ttl_seconds":900,"delegation":{"enabled":true,"mode":"subject"}}`), nil},
		{"audiences list", []string{"audiences", "list"}, "GET", "/v1/manage/audiences", nil, nil},
		{"audiences get", []string{"audiences", "get", "--id", "docs/x"}, "GET", "/v1/manage/audiences/docs%2Fx", nil, nil},
		{"audiences update", []string{"audiences", "update", "--id", "docs", "--display-name="}, "PATCH", "/v1/manage/audiences/docs", apiJSON(`{"display_name":""}`), nil},
		{"audiences delete", []string{"audiences", "delete", "--id", "docs", "--yes"}, "DELETE", "/v1/manage/audiences/docs", nil, nil},
		{"resources create", []string{"resources", "create", "--type", "document", "--id", "one", "--metadata", `{"owner":"a"}`, "--relationship", "parent=folder:f", "--relationship", "reviewer=group:g"}, "POST", "/v1/manage/resources", apiJSON(`{"type":"document","id":"one","metadata":{"owner":"a"},"relationships":{"parent":[{"type":"folder","id":"f"}],"reviewer":[{"type":"group","id":"g"}]}}`), nil},
		{"resources get", []string{"resources", "get", "--type", "document", "--id", "one"}, "GET", "/v1/manage/resources/document/one", nil, nil},
		{"resources update", []string{"resources", "update", "--type", "document", "--id", "one", "--metadata", `{}`}, "PATCH", "/v1/manage/resources/document/one", apiJSON(`{"metadata":{}}`), nil},
		{"resources delete", []string{"resources", "delete", "--type", "document", "--id", "one", "--yes"}, "DELETE", "/v1/manage/resources/document/one", nil, nil},
		{"relationships set one", []string{"relationships", "set", "--resource-type", "document", "--resource-id", "one", "--relation", "parent", "--target", "folder:f"}, "PUT", "/v1/manage/resources/document/one/relationships/parent", apiJSON(`{"target":{"type":"folder","id":"f"}}`), nil},
		{"relationships set many", []string{"relationships", "set", "--resource-type", "document", "--resource-id", "one", "--relation", "reviewer", "--target", "group:a", "--target", "group:b"}, "PUT", "/v1/manage/resources/document/one/relationships/reviewer", apiJSON(`{"targets":[{"type":"group","id":"a"},{"type":"group","id":"b"}]}`), nil},
		{"relationships remove", []string{"relationships", "remove", "--resource-type", "document", "--resource-id", "one", "--relation", "reviewer", "--target", "group:a"}, "DELETE", "/v1/manage/resources/document/one/relationships/reviewer", apiJSON(`{"target":{"type":"group","id":"a"}}`), nil},
		{"relationships remove all", []string{"relationships", "remove", "--resource-type", "document", "--resource-id", "one", "--relation", "reviewer", "--all"}, "DELETE", "/v1/manage/resources/document/one/relationships/reviewer", nil, nil},
		{"groups create", []string{"groups", "create", "--id", "eng", "--display-name", "Engineering"}, "POST", "/v1/manage/groups", apiJSON(`{"id":"eng","display_name":"Engineering"}`), nil},
		{"groups get", []string{"groups", "get", "--id", "eng"}, "GET", "/v1/manage/groups/eng", nil, nil},
		{"groups delete", []string{"groups", "delete", "--id", "eng", "--yes"}, "DELETE", "/v1/manage/groups/eng", nil, nil},
		{"groups add principal", []string{"groups", "add-member", "--id", "eng", "--principal-source", "corp", "--principal-subject", "alice"}, "POST", "/v1/manage/groups/eng/members", apiJSON(`{"member":{"type":"principal","source":"corp","subject":"alice"}}`), nil},
		{"groups remove group", []string{"groups", "remove-member", "--id", "eng", "--group", "interns"}, "DELETE", "/v1/manage/groups/eng/members", apiJSON(`{"member":{"type":"group","group":"interns"}}`), nil},
		{"grants create", []string{"grants", "create", "--id", "g1", "--group", "eng", "--role", "reader", "--resource-type", "document", "--resource-id", "one", "--create-resource-if-missing"}, "POST", "/v1/manage/grants", apiJSON(`{"id":"g1","subject":{"type":"group","group":"eng"},"role":"reader","resource":{"type":"document","id":"one"},"create_resource_if_missing":true}`), nil},
		{"grants list", []string{"grants", "list"}, "GET", "/v1/manage/grants", nil, nil},
		{"grants delete", []string{"grants", "delete", "--id", "g1", "--yes"}, "DELETE", "/v1/manage/grants/g1", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.Method != tt.method {
					t.Errorf("method=%s want %s", r.Method, tt.method)
				}
				if r.URL.EscapedPath() != tt.path {
					t.Errorf("path=%s want %s", r.URL.EscapedPath(), tt.path)
				}
				if r.Header.Get("X-Request-ID") != "test.id" {
					t.Errorf("request id=%q", r.Header.Get("X-Request-ID"))
				}
				if tt.path == "/oauth2/token" {
					if r.Header.Get("Authorization") != "" {
						t.Error("token exchange received bearer token")
					}
				} else if r.Header.Get("Authorization") != "Bearer management.jwt" {
					t.Errorf("authorization=%q", r.Header.Get("Authorization"))
				}
				if tt.form != nil {
					if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
						t.Errorf("content type=%q", r.Header.Get("Content-Type"))
					}
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if r.PostForm.Encode() != tt.form.Encode() {
						t.Errorf("form=%s want %s", r.PostForm.Encode(), tt.form.Encode())
					}
				} else {
					raw, _ := io.ReadAll(r.Body)
					if tt.body != nil && r.Header.Get("Content-Type") != "application/json" {
						t.Errorf("content type=%q", r.Header.Get("Content-Type"))
					}
					if tt.body == nil && len(raw) > 0 {
						t.Errorf("unexpected body %s", raw)
					}
					if tt.body != nil && !sameJSON(raw, tt.body.([]byte)) {
						t.Errorf("body=%s want %s", raw, tt.body)
					}
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			var stdout, stderr bytes.Buffer
			args := append([]string{"--server", server.URL, "--token", "management.jwt", "--request-id", "test.id"}, tt.args...)
			if status := CTL(args, strings.NewReader(""), &stdout, &stderr); status != 0 {
				t.Fatalf("status=%d stderr=%s", status, stderr.String())
			}
			if !called {
				t.Fatal("request not made")
			}
		})
	}
}

func TestCTLValidationDoesNotSendRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("request made") }))
	defer server.Close()
	tests := [][]string{{"audiences", "create", "--id", "x", "--token-ttl", "500ms"}, {"resources", "update", "--type", "document", "--id", "x"}, {"relationships", "remove", "--resource-type", "document", "--resource-id", "x", "--relation", "parent"}, {"groups", "add-member", "--id", "g", "--group", "nested", "--principal-source", "corp", "--principal-subject", "alice"}, {"grants", "create", "--role", "reader", "--resource-type", "document", "--resource-id", "x"}, {"check", "--file", "-", "--permission", "read"}, {"grants", "create", "--group", "eng", "--role", "reader", "--resource-type", "document", "--resource-id", "x", "--create-resource-if-missing=false"}, {"grants", "create", "--id=", "--group", "eng", "--role", "reader", "--resource-type", "document", "--resource-id", "x"}}
	for _, args := range tests {
		var out, err bytes.Buffer
		status := CTL(append([]string{"--server", server.URL}, args...), strings.NewReader(`{"checks":[]}`), &out, &err)
		if status != 2 {
			t.Errorf("%v: status=%d stderr=%s", args, status, err.String())
		}
	}
}

func TestCTLOutputAndAPIError(t *testing.T) {
	t.Run("table", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"results":[{"id":"one","allowed":false}]}`)
		}))
		defer server.Close()
		var out, stderr bytes.Buffer
		status := CTL([]string{"--server", server.URL, "check", "--permission", "read", "--resource-type", "document", "--resource-id", "one"}, strings.NewReader(""), &out, &stderr)
		if status != 0 {
			t.Fatalf("status=%d stderr=%s", status, stderr.String())
		}
		for _, want := range []string{"ID", "ALLOWED", "one", "false"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("table %q missing %q", out.String(), want)
			}
		}
	})
	t.Run("json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{ "audiences": [] }`) }))
		defer server.Close()
		var out, stderr bytes.Buffer
		status := CTL([]string{"--server", server.URL, "--output", "json", "audiences", "list"}, strings.NewReader(""), &out, &stderr)
		if status != 0 {
			t.Fatalf("status=%d stderr=%s", status, stderr.String())
		}
		if out.String() != "{\"audiences\":[]}\n" {
			t.Fatalf("json=%q", out.String())
		}
	})
	t.Run("api error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":"forbidden","message":"no access","request_id":"req-1"}}`)
		}))
		defer server.Close()
		var out, stderr bytes.Buffer
		if status := CTL([]string{"--server", server.URL, "audiences", "list"}, strings.NewReader(""), &out, &stderr); status != 1 {
			t.Fatalf("status=%d", status)
		}
		for _, want := range []string{"403 Forbidden", "forbidden", "no access", "req-1"} {
			if !strings.Contains(stderr.String(), want) {
				t.Errorf("stderr %q missing %q", stderr.String(), want)
			}
		}
	})
}

func TestCTLCommandHelp(t *testing.T) {
	for _, args := range [][]string{{"check", "--help"}, {"audiences", "create", "--help"}, {"relationships", "--help"}} {
		var out, stderr bytes.Buffer
		if status := CTL(args, strings.NewReader(""), &out, &stderr); status != 0 {
			t.Fatalf("%v: status=%d stderr=%s", args, status, stderr.String())
		}
		if !strings.Contains(out.String(), args[0]) {
			t.Errorf("%v: help=%q", args, out.String())
		}
	}
}

func apiJSON(s string) []byte { return []byte(s) }
func sameJSON(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && strings.TrimSpace(string(mustJSON(x))) == strings.TrimSpace(string(mustJSON(y)))
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
