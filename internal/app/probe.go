package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
)

// ProbeRemoteTrust verifies discovery/JWKS endpoints without requiring a real
// identity token. Static trust sources are fully checked by BuildValidator.
func ProbeRemoteTrust(ctx context.Context, cfg *config.Config, client *http.Client) error {
	if client == nil {
		client = http.DefaultClient
	}
	for name, source := range cfg.TokenSources {
		url := source.Keys.JWKSURL
		if source.Keys.Discovery {
			discovery := strings.TrimRight(source.Issuer, "/") + "/.well-known/openid-configuration"
			var document struct {
				Issuer  string `json:"issuer"`
				JWKSURI string `json:"jwks_uri"`
			}
			if err := getJSON(ctx, client, discovery, &document); err != nil {
				return fmt.Errorf("token source %q discovery: %w", name, err)
			}
			if document.JWKSURI == "" {
				return fmt.Errorf("token source %q discovery has no jwks_uri", name)
			}
			if document.Issuer != source.Issuer {
				return fmt.Errorf("token source %q discovery issuer mismatch: configured=%s discovered=%s", name, source.Issuer, document.Issuer)
			}
			url = document.JWKSURI
		}
		if url != "" {
			var set struct {
				Keys []map[string]any `json:"keys"`
			}
			if err := getJSON(ctx, client, url, &set); err != nil {
				return fmt.Errorf("token source %q JWKS: %w", name, err)
			}
			if len(set.Keys) == 0 {
				return fmt.Errorf("token source %q JWKS contains no keys", name)
			}
		}
	}
	return nil
}

func getJSON(ctx context.Context, client *http.Client, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s returned %s", url, resp.Status)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}
	return nil
}
