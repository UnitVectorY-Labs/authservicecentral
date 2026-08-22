package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type Validator struct {
	sources map[string]Source
	now     func() time.Time
}

func NewValidator(sources []Source) (*Validator, error) {
	v := &Validator{sources: make(map[string]Source, len(sources)), now: time.Now}
	ids := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		if source.ID == "" || source.Issuer == "" {
			return nil, errors.New("token source ID and issuer are required")
		}
		if _, exists := v.sources[source.Issuer]; exists {
			return nil, fmt.Errorf("duplicate token source issuer %q", source.Issuer)
		}
		if _, exists := ids[source.ID]; exists {
			return nil, fmt.Errorf("duplicate token source ID %q", source.ID)
		}
		if len(source.Algorithms) == 0 || source.Keys == nil {
			return nil, fmt.Errorf("token source %q requires algorithms and keys", source.ID)
		}
		for _, alg := range source.Algorithms {
			if !supportedAlgorithm(alg) {
				return nil, fmt.Errorf("token source %q has unsupported algorithm %q", source.ID, alg)
			}
		}
		if source.SubjectClaim == "" {
			source.SubjectClaim = "sub"
		}
		if err := validateRules(source.ClaimRules); err != nil {
			return nil, fmt.Errorf("token source %q: %w", source.ID, err)
		}
		for target, mapping := range source.Propagate {
			if target == "" || mapping.From == "" {
				return nil, fmt.Errorf("token source %q has invalid propagation", source.ID)
			}
			if IsReservedClaim(target) {
				return nil, fmt.Errorf("token source %q propagates into reserved claim %q", source.ID, target)
			}
		}
		v.sources[source.Issuer] = source
		ids[source.ID] = struct{}{}
	}
	if len(v.sources) == 0 {
		return nil, errors.New("at least one token source is required")
	}
	return v, nil
}

// Validate identifies a source only after decoding iss, then uses exclusively
// that source's keys and policy to authenticate the JWT.
func (v *Validator) Validate(ctx context.Context, token string) (Identity, error) {
	header, claims, signingInput, signature, err := DecodeCompact(token)
	if err != nil {
		return Identity{}, err
	}
	issuer, ok := claims["iss"].(string)
	if !ok || issuer == "" {
		return Identity{}, errors.New("JWT iss is required")
	}
	source, ok := v.sources[issuer]
	if !ok {
		return Identity{}, fmt.Errorf("untrusted JWT issuer %q", issuer)
	}
	alg, _ := header["alg"].(string)
	if !allowedAlgorithm(source.Algorithms, alg) {
		return Identity{}, fmt.Errorf("JWT algorithm %q is not allowed", alg)
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		return Identity{}, errors.New("JWT kid is required")
	}
	key, err := source.Keys.Key(ctx, kid, alg)
	if err != nil {
		return Identity{}, fmt.Errorf("resolve verification key: %w", err)
	}
	if err := VerifySignature(alg, key, []byte(signingInput), signature); err != nil {
		return Identity{}, fmt.Errorf("verify JWT: %w", err)
	}
	now := v.now()
	if err := validateTimes(claims, now, source.ClockSkew); err != nil {
		return Identity{}, err
	}
	if len(source.AudienceAnyOf) > 0 && !audienceMatches(claims["aud"], source.AudienceAnyOf) {
		return Identity{}, errors.New("JWT audience is not allowed")
	}
	if err := matchClaims(claims, source.ClaimRules); err != nil {
		return Identity{}, err
	}
	subject, ok := claims[source.SubjectClaim].(string)
	if !ok || subject == "" {
		return Identity{}, fmt.Errorf("JWT subject claim %q is required", source.SubjectClaim)
	}
	principal := Principal{Source: source.ID, Subject: subject}
	if err := principal.Validate(); err != nil {
		return Identity{}, err
	}
	propagated := make(map[string]any, len(source.Propagate))
	for target, mapping := range source.Propagate {
		if value, exists := claims[mapping.From]; exists {
			propagated[target] = value
		}
	}
	return Identity{Principal: principal, PropagatedClaims: propagated, Claims: claims}, nil
}

func DecodeCompact(token string) (map[string]any, map[string]any, string, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", nil, errors.New("JWT must have three segments")
	}
	decodeJSON := func(segment string, dst *map[string]any) error {
		b, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			return err
		}
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.UseNumber()
		return dec.Decode(dst)
	}
	var header, claims map[string]any
	if err := decodeJSON(parts[0], &header); err != nil {
		return nil, nil, "", nil, errors.New("invalid JWT header")
	}
	if err := decodeJSON(parts[1], &claims); err != nil {
		return nil, nil, "", nil, errors.New("invalid JWT claims")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, "", nil, errors.New("invalid JWT signature encoding")
	}
	return header, claims, parts[0] + "." + parts[1], sig, nil
}

func VerifySignature(alg string, key crypto.PublicKey, signingInput, signature []byte) error {
	var hash crypto.Hash
	switch alg {
	case "RS256", "ES256":
		hash = crypto.SHA256
	case "RS384", "ES384":
		hash = crypto.SHA384
	case "RS512", "ES512":
		hash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported algorithm %q", alg)
	}
	h := hash.New()
	h.Write(signingInput)
	digest := h.Sum(nil)
	switch {
	case strings.HasPrefix(alg, "RS"):
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("RSA algorithm requires RSA key")
		}
		return rsa.VerifyPKCS1v15(rsaKey, hash, digest, signature)
	case strings.HasPrefix(alg, "ES"):
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("EC algorithm requires EC key")
		}
		expectedBits := map[string]int{"ES256": 256, "ES384": 384, "ES512": 521}[alg]
		if ecKey.Curve.Params().BitSize != expectedBits {
			return fmt.Errorf("%s requires a matching EC curve", alg)
		}
		size := (ecKey.Curve.Params().BitSize + 7) / 8
		if len(signature) != size*2 {
			return errors.New("invalid ECDSA signature length")
		}
		r, s := new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(ecKey, digest, r, s) {
			return errors.New("invalid ECDSA signature")
		}
		return nil
	}
	return errors.New("unsupported signature")
}

func supportedAlgorithm(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
		return true
	default:
		return false
	}
}

func allowedAlgorithm(allowed []string, alg string) bool {
	if alg == "" || alg == "none" {
		return false
	}
	for _, candidate := range allowed {
		if candidate == alg {
			return true
		}
	}
	return false
}

func validateTimes(claims map[string]any, now time.Time, skew time.Duration) error {
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return errors.New("JWT exp is required and must be numeric")
	}
	if !now.Add(-skew).Before(time.Unix(exp, 0)) {
		return errors.New("JWT is expired")
	}
	if raw, exists := claims["nbf"]; exists {
		nbf, ok := numericDate(raw)
		if !ok {
			return errors.New("JWT nbf must be numeric")
		}
		if now.Add(skew).Before(time.Unix(nbf, 0)) {
			return errors.New("JWT is not yet valid")
		}
	}
	return nil
}

func numericDate(value any) (int64, bool) {
	switch n := value.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case float64:
		return int64(n), n == float64(int64(n))
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

func audienceMatches(value any, allowed []string) bool {
	wanted := make(map[string]struct{}, len(allowed))
	for _, audience := range allowed {
		wanted[audience] = struct{}{}
	}
	switch aud := value.(type) {
	case string:
		_, ok := wanted[aud]
		return ok
	case []any:
		for _, item := range aud {
			if s, ok := item.(string); ok {
				if _, found := wanted[s]; found {
					return true
				}
			}
		}
	}
	return false
}
