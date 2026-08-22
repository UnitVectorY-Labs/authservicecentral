package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/api"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

func TestDomainErrorTaxonomy(t *testing.T) {
	if !errors.Is(domainError(database.ErrNotFound), api.ErrNotFound) {
		t.Fatal("not-found mapping")
	}
	var apiErr *api.APIError
	if !errors.As(domainError(database.ErrCardinality), &apiErr) || apiErr.Status != http.StatusBadRequest {
		t.Fatal("cardinality mapping")
	}
	if !errors.As(domainError(errors.New(`unknown permission "x"`)), &apiErr) || apiErr.Status != http.StatusBadRequest {
		t.Fatal("validation mapping")
	}
	internal := errors.New("connection reset")
	if domainError(internal) != internal {
		t.Fatal("internal error must remain internal")
	}
}

func TestProbeRemoteTrustChecksDiscoveryIssuerAndJWKS(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/keys"}`
		if r.URL.Path == "/keys" {
			body = `{"keys":[{"kid":"one"}]}`
		}
		return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	cfg := &config.Config{TokenSources: map[string]config.TokenSource{"test": {Issuer: "https://issuer.example", Keys: config.Keys{Discovery: true}}}}
	if err := ProbeRemoteTrust(t.Context(), cfg, client); err != nil {
		t.Fatal(err)
	}
	cfg.TokenSources["test"] = config.TokenSource{Issuer: "https://issuer.example/wrong", Keys: config.Keys{Discovery: true}}
	if err := ProbeRemoteTrust(t.Context(), cfg, client); err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("expected issuer mismatch, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDrainOutboxRejectsUnboundedConfiguration(t *testing.T) {
	if err := DrainOutbox(context.Background(), nil, 0, 1); err == nil {
		t.Fatal("expected batch validation")
	}
	if err := DrainOutbox(context.Background(), nil, 1, 0); err == nil {
		t.Fatal("expected round validation")
	}
}
