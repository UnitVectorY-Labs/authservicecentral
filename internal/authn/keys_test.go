package authn

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteKeysDiscoveryCacheAndUnknownKIDRefresh(t *testing.T) {
	one, two := mustRSA(t), mustRSA(t)
	var jwksCalls atomic.Int32
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body any
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			body = map[string]any{"issuer": "https://issuer.test", "jwks_uri": "https://issuer.test/keys"}
		case "/keys":
			call := jwksCalls.Add(1)
			keys := []map[string]any{rsaJWK("one", &one.PublicKey)}
			if call > 1 {
				keys = append(keys, rsaJWK("two", &two.PublicKey))
			}
			body = JWKSet{Keys: keys}
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
		}
		encoded, _ := json.Marshal(body)
		header := make(http.Header)
		header.Set("Cache-Control", "public, max-age=3600")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)), Header: header}, nil
	})
	remote := &RemoteKeys{Issuer: "https://issuer.test", Discovery: true, Client: &http.Client{Transport: transport}, DefaultTTL: time.Minute}
	if _, err := remote.Key(context.Background(), "one", "RS256"); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Key(context.Background(), "one", "RS256"); err != nil {
		t.Fatal(err)
	}
	if got := jwksCalls.Load(); got != 1 {
		t.Fatalf("cached key caused %d JWKS calls", got)
	}
	if _, err := remote.Key(context.Background(), "two", "RS256"); err != nil {
		t.Fatal(err)
	}
	if got := jwksCalls.Load(); got != 2 {
		t.Fatalf("unknown kid refresh caused %d calls", got)
	}
	if _, err := remote.Key(context.Background(), "missing", "RS256"); err == nil {
		t.Fatal("unknown key accepted")
	}
	if got := jwksCalls.Load(); got != 3 {
		t.Fatalf("unknown kid was not bounded to one refresh: %d", got)
	}
}

func TestRemoteDiscoveryRejectsIssuerMismatch(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		encoded, _ := json.Marshal(map[string]any{"issuer": "wrong", "jwks_uri": "https://example.test/keys"})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)), Header: make(http.Header)}, nil
	})}
	remote := &RemoteKeys{Issuer: "https://issuer.test", Discovery: true, Client: client}
	if _, err := remote.Key(context.Background(), "x", "RS256"); err == nil {
		t.Fatal("issuer mismatch accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func rsaJWK(kid string, key *rsa.PublicKey) map[string]any {
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{"kty": "RSA", "kid": kid, "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}
}
