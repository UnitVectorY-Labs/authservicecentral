package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/jwt"
)

func newTestServer(t *testing.T, dataPlane bool) *Server {
	t.Helper()

	cfg := &config.Config{
		DataPlaneEnabled:    dataPlane,
		ControlPlaneEnabled: false,
		JWTIssuer:           "https://auth.example.com",
	}

	// Generate a test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	keyStore := &jwt.KeyStore{
		SigningKey: &jwt.Key{
			Kid:        "test-kid",
			Algorithm:  "RS256",
			PrivateKey: rsaKey,
			PublicKey:  &rsaKey.PublicKey,
		},
		AllKeys: []*jwt.Key{
			{
				Kid:       "test-kid",
				Algorithm: "RS256",
				PublicKey: &rsaKey.PublicKey,
			},
		},
	}

	return NewServer(cfg, nil, keyStore)
}

func TestHealthz(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
}

func TestOpenIDConfiguration(t *testing.T) {
	srv := newTestServer(t, true)

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	if body["issuer"] != "https://auth.example.com" {
		t.Errorf("issuer = %v, want %q", body["issuer"], "https://auth.example.com")
	}
	if body["jwks_uri"] != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %v", body["jwks_uri"])
	}
	if body["token_endpoint"] != "https://auth.example.com/v1/token" {
		t.Errorf("token_endpoint = %v", body["token_endpoint"])
	}

	grants, ok := body["grant_types_supported"].([]interface{})
	if !ok || len(grants) != 2 {
		t.Errorf("grant_types_supported = %v", body["grant_types_supported"])
	}
}

func TestJWKSEndpoint(t *testing.T) {
	srv := newTestServer(t, true)

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	keys, ok := body["keys"].([]interface{})
	if !ok || len(keys) != 1 {
		t.Fatalf("keys = %v, want 1 key", body["keys"])
	}

	key := keys[0].(map[string]interface{})
	if key["kty"] != "RSA" {
		t.Errorf("kty = %v, want RSA", key["kty"])
	}
	if key["use"] != "sig" {
		t.Errorf("use = %v, want sig", key["use"])
	}
	if key["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", key["alg"])
	}
}

func TestJWKSEndpointMultipleKeys(t *testing.T) {
	cfg := &config.Config{
		DataPlaneEnabled: true,
		JWTIssuer:        "https://auth.example.com",
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	keyStore := &jwt.KeyStore{
		AllKeys: []*jwt.Key{
			{Kid: "rsa-kid", Algorithm: "RS256", PublicKey: &rsaKey.PublicKey},
			{Kid: "ec-kid", Algorithm: "ES256", PublicKey: &ecKey.PublicKey},
		},
	}

	srv := NewServer(cfg, nil, keyStore)

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)

	keys := body["keys"].([]interface{})
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestDataPlaneDisabled(t *testing.T) {
	srv := newTestServer(t, false)

	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/jwks.json"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Errorf("path %s should not be available when data plane is disabled", path)
		}
	}
}
