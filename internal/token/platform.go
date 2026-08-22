// Package token issues and validates platform JWTs and implements token
// exchange domain orchestration independently of HTTP transport.
package token

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/authn"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/signing"
)

type DelegationMode string

const (
	DelegationDisabled     DelegationMode = "disabled"
	DelegationSubject      DelegationMode = "subject"
	DelegationIntersection DelegationMode = "intersection"
	DelegationActor        DelegationMode = "actor"
	DelegationUnion        DelegationMode = "union"
)

type Actor struct {
	Subject string `json:"sub"`
}

type AuthorizationContext struct {
	Mode    DelegationMode   `json:"delegation_mode,omitempty"`
	Subject authn.Principal  `json:"subject"`
	Actor   *authn.Principal `json:"actor,omitempty"`
}

type Claims struct {
	Issuer               string               `json:"iss"`
	Subject              string               `json:"sub"`
	Audience             string               `json:"aud"`
	IssuedAt             int64                `json:"iat"`
	ExpiresAt            int64                `json:"exp"`
	JWTID                string               `json:"jti"`
	Permissions          []string             `json:"permissions"`
	Act                  *Actor               `json:"act,omitempty"`
	AuthorizationContext AuthorizationContext `json:"authorization_context"`
	Extra                map[string]any       `json:"-"`
}

type Issuer struct {
	Issuer    string
	Signer    signing.Signer
	Published []signing.Signer
	Now       func() time.Time
}

func (i *Issuer) Issue(ctx context.Context, principal authn.Principal, actor *authn.Principal, audience string, ttl time.Duration, permissions []string, mode DelegationMode, extra map[string]any) (string, Claims, error) {
	if i.Signer == nil || i.Issuer == "" {
		return "", Claims{}, errors.New("platform issuer and signer are required")
	}
	if err := principal.Validate(); err != nil {
		return "", Claims{}, err
	}
	if audience == "" || ttl <= 0 {
		return "", Claims{}, errors.New("audience and positive TTL are required")
	}
	for name := range extra {
		if authn.IsReservedClaim(name) {
			return "", Claims{}, fmt.Errorf("extra claim %q is reserved", name)
		}
	}
	now := time.Now()
	if i.Now != nil {
		now = i.Now()
	}
	claims := Claims{Issuer: i.Issuer, Subject: principal.String(), Audience: audience, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(), JWTID: randomID(), Permissions: sortedUnique(permissions), AuthorizationContext: AuthorizationContext{Mode: mode, Subject: principal, Actor: actor}, Extra: cloneMap(extra)}
	if actor != nil {
		claims.Act = &Actor{Subject: actor.String()}
	}
	header := map[string]any{"typ": "JWT", "alg": i.Signer.Algorithm(), "kid": i.Signer.KeyID()}
	payload := claimsMap(claims)
	encodedHeader, err := encodeJSON(header)
	if err != nil {
		return "", Claims{}, err
	}
	encodedPayload, err := encodeJSON(payload)
	if err != nil {
		return "", Claims{}, err
	}
	input := encodedHeader + "." + encodedPayload
	h := i.Signer.Hash().New()
	h.Write([]byte(input))
	digest := h.Sum(nil)
	sig, err := i.Signer.Sign(ctx, digest)
	if err != nil {
		return "", Claims{}, fmt.Errorf("sign platform JWT: %w", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), claims, nil
}

func (i *Issuer) JWKS(ctx context.Context) (map[string]any, error) {
	signers := append([]signing.Signer{i.Signer}, i.Published...)
	keys, seen := make([]signing.JWK, 0, len(signers)), map[string]struct{}{}
	for _, signer := range signers {
		if signer == nil {
			continue
		}
		if _, ok := seen[signer.KeyID()]; ok {
			continue
		}
		jwk, err := signer.PublicJWK(ctx)
		if err != nil {
			return nil, err
		}
		keys = append(keys, jwk)
		seen[signer.KeyID()] = struct{}{}
	}
	return map[string]any{"keys": keys}, nil
}

type Parser struct {
	Issuer     string
	Algorithms []string
	Keys       authn.KeyProvider
	ClockSkew  time.Duration
	Now        func() time.Time
}

func (p *Parser) Parse(ctx context.Context, token, expectedAudience string) (Claims, error) {
	if p.Issuer == "" || p.Keys == nil || len(p.Algorithms) == 0 {
		return Claims{}, errors.New("platform parser is not configured")
	}
	header, raw, input, sig, err := authn.DecodeCompact(token)
	if err != nil {
		return Claims{}, err
	}
	alg, _ := header["alg"].(string)
	if !containsString(p.Algorithms, alg) {
		return Claims{}, fmt.Errorf("platform JWT algorithm %q is not allowed", alg)
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		return Claims{}, errors.New("platform JWT kid is required")
	}
	key, err := p.Keys.Key(ctx, kid, alg)
	if err != nil {
		return Claims{}, err
	}
	if err := authn.VerifySignature(alg, key, []byte(input), sig); err != nil {
		return Claims{}, err
	}
	issuer, _ := raw["iss"].(string)
	if issuer != p.Issuer {
		return Claims{}, errors.New("unexpected platform JWT issuer")
	}
	aud, _ := raw["aud"].(string)
	if expectedAudience != "" && aud != expectedAudience {
		return Claims{}, errors.New("unexpected platform JWT audience")
	}
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	exp, ok := numberInt64(raw["exp"])
	if !ok || !now.Add(-p.ClockSkew).Before(time.Unix(exp, 0)) {
		return Claims{}, errors.New("platform JWT is expired or has invalid exp")
	}
	iat, ok := numberInt64(raw["iat"])
	if !ok || now.Add(p.ClockSkew).Before(time.Unix(iat, 0)) {
		return Claims{}, errors.New("platform JWT has invalid iat")
	}
	b, _ := json.Marshal(raw)
	var claims Claims
	if err := json.Unmarshal(b, &claims); err != nil {
		return Claims{}, err
	}
	if claims.Subject == "" || claims.Audience == "" || claims.JWTID == "" {
		return Claims{}, errors.New("platform JWT required claims are missing")
	}
	claims.Extra = make(map[string]any)
	for name, value := range raw {
		if !authn.IsReservedClaim(name) {
			claims.Extra[name] = value
		}
	}
	if err := claims.AuthorizationContext.Subject.Validate(); err != nil {
		return Claims{}, errors.New("platform JWT authorization context is invalid")
	}
	if claims.Subject != claims.AuthorizationContext.Subject.String() {
		return Claims{}, errors.New("platform JWT subject and authorization context do not match")
	}
	if claims.Act == nil && claims.AuthorizationContext.Actor != nil || claims.Act != nil && claims.AuthorizationContext.Actor == nil {
		return Claims{}, errors.New("platform JWT actor context is inconsistent")
	}
	if claims.Act != nil && claims.Act.Subject != claims.AuthorizationContext.Actor.String() {
		return Claims{}, errors.New("platform JWT actor subjects do not match")
	}
	return claims, nil
}

func claimsMap(c Claims) map[string]any {
	m := cloneMap(c.Extra)
	m["iss"], m["sub"], m["aud"] = c.Issuer, c.Subject, c.Audience
	m["iat"], m["exp"], m["jti"] = c.IssuedAt, c.ExpiresAt, c.JWTID
	m["permissions"] = c.Permissions
	m["authorization_context"] = c.AuthorizationContext
	if c.Act != nil {
		m["act"] = c.Act
	}
	return m
}

func encodeJSON(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func sortedUnique(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func numberInt64(value any) (int64, bool) {
	switch n := value.(type) {
	case json.Number:
		i, e := n.Int64()
		return i, e == nil
	case float64:
		return int64(n), n == float64(int64(n))
	case int64:
		return n, true
	}
	return 0, false
}

// CombinePermissions applies the configured delegation semantics.
func CombinePermissions(mode DelegationMode, subject, actor []string) ([]string, error) {
	s, a := map[string]struct{}{}, map[string]struct{}{}
	for _, p := range subject {
		s[p] = struct{}{}
	}
	for _, p := range actor {
		a[p] = struct{}{}
	}
	var out []string
	switch mode {
	case DelegationSubject:
		out = append(out, subject...)
	case DelegationActor:
		out = append(out, actor...)
	case DelegationIntersection:
		for p := range s {
			if _, ok := a[p]; ok {
				out = append(out, p)
			}
		}
	case DelegationUnion:
		out = append(out, subject...)
		out = append(out, actor...)
	case DelegationDisabled:
		return nil, errors.New("delegation is disabled")
	default:
		return nil, fmt.Errorf("unknown delegation mode %q", mode)
	}
	return sortedUnique(out), nil
}
