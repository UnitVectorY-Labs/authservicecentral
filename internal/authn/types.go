// Package authn validates JWTs from explicitly configured trust sources.
package authn

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// Principal is the authorization identity derived from a token source and its
// configured subject claim. Principals do not need to be provisioned.
type Principal struct {
	Source  string `json:"source"`
	Subject string `json:"subject"`
}

func (p Principal) Validate() error {
	if strings.TrimSpace(p.Source) == "" || strings.TrimSpace(p.Subject) == "" {
		return errors.New("principal source and subject are required")
	}
	return nil
}

// String is the human-readable representation used in platform JWT subjects.
func (p Principal) String() string { return p.Source + ":" + p.Subject }

// Canonical returns an unambiguous identifier suitable for OpenFGA object IDs.
func (p Principal) Canonical() string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(p.Source)) + "." + enc([]byte(p.Subject))
}

func ParseCanonical(value string) (Principal, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return Principal{}, errors.New("invalid canonical principal")
	}
	dec := base64.RawURLEncoding.DecodeString
	source, err := dec(parts[0])
	if err != nil {
		return Principal{}, errors.New("invalid canonical principal source")
	}
	subject, err := dec(parts[1])
	if err != nil {
		return Principal{}, errors.New("invalid canonical principal subject")
	}
	p := Principal{Source: string(source), Subject: string(subject)}
	return p, p.Validate()
}

type Identity struct {
	Principal        Principal
	PropagatedClaims map[string]any
	Claims           map[string]any
}

// ClaimRule deliberately supports a small, auditable matcher vocabulary. A
// rule must set exactly one operation.
type ClaimRule struct {
	Exists    *bool
	Equals    any
	NotEquals any
	OneOf     []any
	Prefix    *string
	Suffix    *string
	Regex     *string
	Contains  any
}

type Propagation struct {
	From string
}

type Source struct {
	ID            string
	Issuer        string
	Algorithms    []string
	AudienceAnyOf []string
	SubjectClaim  string
	ClaimRules    map[string]ClaimRule
	Propagate     map[string]Propagation
	Keys          KeyProvider
	ClockSkew     time.Duration
}

var reservedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "iat": {}, "nbf": {},
	"jti": {}, "act": {}, "permissions": {}, "authorization_context": {},
}

func IsReservedClaim(name string) bool {
	_, ok := reservedClaims[name]
	return ok
}
