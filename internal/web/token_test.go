package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestTokenEndpointMissingGrantType(t *testing.T) {
	srv := newTestServer(t, true)

	form := url.Values{}
	req := httptest.NewRequest("POST", "/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var body oauthError
	json.NewDecoder(w.Body).Decode(&body)
	if body.Error != errInvalidRequest {
		t.Errorf("error = %q, want %q", body.Error, errInvalidRequest)
	}
	if body.ErrorDescription != "grant_type is required" {
		t.Errorf("error_description = %q", body.ErrorDescription)
	}
}

func TestTokenEndpointUnsupportedGrantType(t *testing.T) {
	srv := newTestServer(t, true)

	form := url.Values{"grant_type": {"authorization_code"}}
	req := httptest.NewRequest("POST", "/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var body oauthError
	json.NewDecoder(w.Body).Decode(&body)
	if body.Error != errInvalidRequest {
		t.Errorf("error = %q, want %q", body.Error, errInvalidRequest)
	}
}

func TestTokenEndpointJWTBearerNotSupported(t *testing.T) {
	srv := newTestServer(t, true)

	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}}
	req := httptest.NewRequest("POST", "/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var body oauthError
	json.NewDecoder(w.Body).Decode(&body)
	if body.Error != errInvalidGrant {
		t.Errorf("error = %q, want %q", body.Error, errInvalidGrant)
	}
}

func TestTokenEndpointClientCredentialsMissingClientID(t *testing.T) {
	srv := newTestServer(t, true)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_secret": {"secret"},
		"audience":      {"service-b"},
	}
	req := httptest.NewRequest("POST", "/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var body oauthError
	json.NewDecoder(w.Body).Decode(&body)
	if body.Error != errInvalidRequest {
		t.Errorf("error = %q, want %q", body.Error, errInvalidRequest)
	}
}

func TestTokenEndpointClientCredentialsMissingSecret(t *testing.T) {
	srv := newTestServer(t, true)

	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"client-123"},
		"audience":   {"service-b"},
	}
	req := httptest.NewRequest("POST", "/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var body oauthError
	json.NewDecoder(w.Body).Decode(&body)
	if body.Error != errInvalidRequest {
		t.Errorf("error = %q, want %q", body.Error, errInvalidRequest)
	}
}

func TestTokenEndpointClientCredentialsMissingAudience(t *testing.T) {
	srv := newTestServer(t, true)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"client-123"},
		"client_secret": {"secret"},
	}
	req := httptest.NewRequest("POST", "/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var body oauthError
	json.NewDecoder(w.Body).Decode(&body)
	if body.Error != errInvalidRequest {
		t.Errorf("error = %q, want %q", body.Error, errInvalidRequest)
	}
	if body.ErrorDescription != "audience is required" {
		t.Errorf("error_description = %q, want %q", body.ErrorDescription, "audience is required")
	}
}

func TestTokenEndpointDisabledDataPlane(t *testing.T) {
	srv := newTestServer(t, false)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"client-123"},
		"client_secret": {"secret"},
		"audience":      {"service-b"},
	}
	req := httptest.NewRequest("POST", "/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Should get 405 or 404 since token endpoint isn't registered
	if w.Code == http.StatusOK {
		t.Error("token endpoint should not be available when data plane is disabled")
	}
}

func TestTokenEndpointResponseHeaders(t *testing.T) {
	srv := newTestServer(t, true)

	form := url.Values{"grant_type": {"client_credentials"}}
	req := httptest.NewRequest("POST", "/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}
