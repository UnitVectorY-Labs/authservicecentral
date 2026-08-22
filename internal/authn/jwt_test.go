package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"
)

func TestValidatorRSAClaimsAndPropagation(t *testing.T) {
	key := mustRSA(t)
	keys, err := NewStaticPEM("one", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustPublicDER(t, &key.PublicKey)}))
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	prefix, suffix, pattern := "refs/heads/", ".com", `^repo:[a-z]+$`
	source := Source{ID: "github", Issuer: "https://issuer.test", Algorithms: []string{"RS256"}, AudienceAnyOf: []string{"serviceauth"}, Keys: keys,
		ClaimRules: map[string]ClaimRule{
			"repository": {Regex: &pattern}, "ref": {Prefix: &prefix}, "email": {Suffix: &suffix},
			"owner": {Equals: "example"}, "event": {OneOf: []any{"push", "dispatch"}}, "blocked": {NotEquals: true},
			"groups": {Contains: "engineering"}, "required": {Exists: &yes},
		}, Propagate: map[string]Propagation{"repository_name": {From: "repository"}}}
	v, err := NewValidator([]Source{source})
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return time.Unix(1_000, 0) }
	claims := map[string]any{"iss": source.Issuer, "sub": "alice:with:colons", "aud": []string{"other", "serviceauth"}, "exp": 1100, "nbf": 900,
		"repository": "repo:docs", "ref": "refs/heads/main", "email": "a@example.com", "owner": "example", "event": "push", "blocked": false, "groups": []any{"engineering"}, "required": 0}
	token := signRSA(t, key, "one", "RS256", claims)
	identity, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Principal.String() != "github:alice:with:colons" || identity.PropagatedClaims["repository_name"] != "repo:docs" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	canonical := identity.Principal.Canonical()
	parsed, err := ParseCanonical(canonical)
	if err != nil || parsed != identity.Principal {
		t.Fatalf("canonical round trip: %#v %v", parsed, err)
	}

	bad := cloneClaims(claims)
	bad["owner"] = "other"
	if _, err := v.Validate(context.Background(), signRSA(t, key, "one", "RS256", bad)); err == nil {
		t.Fatal("claim mismatch accepted")
	}
	bad = cloneClaims(claims)
	bad["aud"] = "wrong"
	if _, err := v.Validate(context.Background(), signRSA(t, key, "one", "RS256", bad)); err == nil {
		t.Fatal("wrong audience accepted")
	}
	bad = cloneClaims(claims)
	bad["exp"] = 999
	if _, err := v.Validate(context.Background(), signRSA(t, key, "one", "RS256", bad)); err == nil {
		t.Fatal("expired token accepted")
	}
	bad = cloneClaims(claims)
	bad["nbf"] = 1001
	if _, err := v.Validate(context.Background(), signRSA(t, key, "one", "RS256", bad)); err == nil {
		t.Fatal("future token accepted")
	}
	bad = cloneClaims(claims)
	bad["iss"] = "https://other.test"
	if _, err := v.Validate(context.Background(), signRSA(t, key, "one", "RS256", bad)); err == nil {
		t.Fatal("untrusted issuer accepted")
	}
	if _, err := v.Validate(context.Background(), signRSA(t, key, "one", "RS512", claims)); err == nil {
		t.Fatal("unlisted algorithm accepted")
	}
	other := mustRSA(t)
	if _, err := v.Validate(context.Background(), signRSA(t, other, "one", "RS256", claims)); err == nil {
		t.Fatal("wrong signature accepted")
	}
}

func TestValidatorECDSAAndValidationErrors(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := ecJWK("ec", &key.PublicKey)
	keys, err := NewStaticJWKs([]map[string]any{jwk})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewValidator([]Source{{ID: "corp", Issuer: "corp-issuer", Algorithms: []string{"ES256"}, Keys: keys}})
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return time.Unix(1000, 0) }
	token := signEC(t, key, "ec", map[string]any{"iss": "corp-issuer", "sub": "42", "exp": 1100})
	if _, err := v.Validate(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if _, err := NewValidator([]Source{{ID: "x", Issuer: "i", Algorithms: []string{"RS256"}, Keys: keys, Propagate: map[string]Propagation{"sub": {From: "name"}}}}); err == nil {
		t.Fatal("reserved propagation accepted")
	}
	if _, err := NewValidator([]Source{{ID: "x", Issuer: "i", Algorithms: []string{"RS256"}, Keys: keys, ClaimRules: map[string]ClaimRule{"x": {}}}}); err == nil {
		t.Fatal("empty matcher accepted")
	}
}

func signRSA(t *testing.T, key *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	t.Helper()
	input := segments(t, map[string]any{"alg": alg, "kid": kid}, claims)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func signEC(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	input := segments(t, map[string]any{"alg": "ES256", "kid": kid}, claims)
	d := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	size := 32
	sig := make([]byte, size*2)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func segments(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	encode := func(v any) string {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return encode(header) + "." + encode(claims)
}
func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func mustPublicDER(t *testing.T, key any) []byte {
	t.Helper()
	b, e := x509.MarshalPKIXPublicKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func cloneClaims(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func ecJWK(kid string, key *ecdsa.PublicKey) map[string]any {
	enc := base64.RawURLEncoding.EncodeToString
	size := 32
	x, y := make([]byte, size), make([]byte, size)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	return map[string]any{"kty": "EC", "kid": kid, "crv": "P-256", "x": enc(x), "y": enc(y)}
}
