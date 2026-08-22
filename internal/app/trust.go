// Package app wires deployment configuration into runtime domain components.
package app

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/authn"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/token"
)

func BuildValidator(cfg *config.Config, client *http.Client) (*authn.Validator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("build trust manager: configuration is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cfg.TokenSources))
	for name := range cfg.TokenSources {
		names = append(names, name)
	}
	sort.Strings(names)
	sources := make([]authn.Source, 0, len(names))
	for _, name := range names {
		definition := cfg.TokenSources[name]
		keys, err := keyProvider(definition, client)
		if err != nil {
			return nil, fmt.Errorf("token source %q: %w", name, err)
		}
		source := authn.Source{ID: definition.Identity.Prefix, Issuer: definition.Issuer, Algorithms: append([]string(nil), definition.Algorithms...), SubjectClaim: definition.Identity.SubjectClaim, ClaimRules: map[string]authn.ClaimRule{}, Propagate: map[string]authn.Propagation{}, Keys: keys}
		if definition.Validation.Audience != nil {
			source.AudienceAnyOf, err = audienceValues(*definition.Validation.Audience)
			if err != nil {
				return nil, fmt.Errorf("token source %q audience: %w", name, err)
			}
		}
		for claim, rule := range definition.Validation.Claims {
			source.ClaimRules[claim] = claimRule(rule)
		}
		for target, propagation := range definition.PropagateClaims {
			source.Propagate[target] = authn.Propagation{From: propagation.From}
		}
		sources = append(sources, source)
	}
	return authn.NewValidator(sources)
}

// ExchangeValidator accepts both explicitly trusted external JWTs and
// platform JWTs from a preceding hop, enabling RFC 8693 on-behalf-of flows.
// Both paths perform full cryptographic and time validation.
type ExchangeValidator struct {
	External *authn.Validator
	Platform *token.Parser
}

func (v ExchangeValidator) Validate(ctx context.Context, raw string) (authn.Identity, error) {
	if v.External != nil {
		if identity, err := v.External.Validate(ctx, raw); err == nil {
			return identity, nil
		}
	}
	if v.Platform == nil {
		return authn.Identity{}, fmt.Errorf("token is not valid for any trusted source")
	}
	claims, err := v.Platform.Parse(ctx, raw, "")
	if err != nil {
		return authn.Identity{}, fmt.Errorf("token is not valid for any trusted source")
	}
	principal := claims.AuthorizationContext.Subject
	return authn.Identity{Principal: principal, PropagatedClaims: claims.Extra}, nil
}

func keyProvider(source config.TokenSource, client *http.Client) (authn.KeyProvider, error) {
	switch {
	case len(source.Keys.JWKS) > 0:
		b, err := json.Marshal(source.Keys.JWKS)
		if err != nil {
			return nil, err
		}
		// Inline JWKS accepts the natural {keys:[...]} object. A single inline
		// JWK object is also accepted for convenient deployment YAML.
		if _, ok := source.Keys.JWKS["keys"]; ok {
			return authn.NewStaticJWKS(b)
		}
		return authn.NewStaticJWKs([]map[string]any{source.Keys.JWKS})
	case source.Keys.PublicKey != "":
		block, _ := pem.Decode([]byte(source.Keys.PublicKey))
		if block == nil {
			return nil, fmt.Errorf("static public key is not PEM")
		}
		public, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse static public key: %w", err)
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, fmt.Errorf("marshal static public key: %w", err)
		}
		digest := sha256.Sum256(der)
		kid := base64.RawURLEncoding.EncodeToString(digest[:])
		return authn.NewStaticPEM(kid, []byte(source.Keys.PublicKey))
	case source.Keys.Discovery:
		return &authn.RemoteKeys{Issuer: source.Issuer, Discovery: true, Client: client, DefaultTTL: 5 * time.Minute}, nil
	case source.Keys.JWKSURL != "":
		return &authn.RemoteKeys{Issuer: source.Issuer, JWKSURL: source.Keys.JWKSURL, Client: client, DefaultTTL: 5 * time.Minute}, nil
	default:
		return nil, fmt.Errorf("no key provider configured")
	}
}

func claimRule(in config.Matcher) authn.ClaimRule {
	out := authn.ClaimRule{Exists: in.Exists, Equals: in.Equals, NotEquals: in.NotEquals, OneOf: in.OneOf, Contains: in.Contains}
	if len(in.AnyOf) > 0 {
		out.OneOf = in.AnyOf
	}
	if in.Prefix != "" {
		out.Prefix = &in.Prefix
	}
	if in.Suffix != "" {
		out.Suffix = &in.Suffix
	}
	if in.Regex != "" {
		out.Regex = &in.Regex
	}
	return out
}

func audienceValues(m config.Matcher) ([]string, error) {
	values := m.OneOf
	if len(m.AnyOf) > 0 {
		values = m.AnyOf
	}
	if m.Equals != nil {
		values = []any{m.Equals}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("audience validation must use equals, one_of, or any_of")
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		s, ok := value.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("audience values must be non-empty strings")
		}
		out = append(out, s)
	}
	return out, nil
}
