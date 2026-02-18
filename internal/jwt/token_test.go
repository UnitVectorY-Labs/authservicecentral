package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignTokenRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	ks := &KeyStore{
		SigningKey: &Key{
			Kid:        "test-rsa-kid",
			Algorithm:  "RS256",
			PrivateKey: rsaKey,
			PublicKey:  &rsaKey.PublicKey,
		},
	}

	claims := &Claims{
		Issuer:   "https://auth.example.com",
		Subject:  "service-a",
		Audience: "service-b",
		Exp:      time.Now().Add(time.Hour).Unix(),
		Iat:      time.Now().Unix(),
		Jti:      "test-jti-123",
		Scope:    "read write",
	}

	token, err := ks.SignToken(claims)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	// Verify token has 3 parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Decode and verify header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header["alg"] != "RS256" {
		t.Errorf("header alg = %q, want RS256", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("header typ = %q, want JWT", header["typ"])
	}
	if header["kid"] != "test-rsa-kid" {
		t.Errorf("header kid = %q, want test-rsa-kid", header["kid"])
	}

	// Decode and verify claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var decoded Claims
	if err := json.Unmarshal(claimsJSON, &decoded); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if decoded.Issuer != "https://auth.example.com" {
		t.Errorf("iss = %q, want https://auth.example.com", decoded.Issuer)
	}
	if decoded.Subject != "service-a" {
		t.Errorf("sub = %q, want service-a", decoded.Subject)
	}
	if decoded.Audience != "service-b" {
		t.Errorf("aud = %q, want service-b", decoded.Audience)
	}
	if decoded.Scope != "read write" {
		t.Errorf("scope = %q, want 'read write'", decoded.Scope)
	}

	// Verify signature
	err = VerifyTokenSignature(token, &rsaKey.PublicKey, "RS256")
	if err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestSignTokenEC(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}

	ks := &KeyStore{
		SigningKey: &Key{
			Kid:        "test-ec-kid",
			Algorithm:  "ES256",
			PrivateKey: ecKey,
			PublicKey:  &ecKey.PublicKey,
		},
	}

	claims := &Claims{
		Issuer:   "https://auth.example.com",
		Subject:  "service-a",
		Audience: "service-b",
		Exp:      time.Now().Add(time.Hour).Unix(),
		Iat:      time.Now().Unix(),
		Jti:      "test-jti-456",
	}

	token, err := ks.SignToken(claims)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	err = VerifyTokenSignature(token, &ecKey.PublicKey, "ES256")
	if err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestSignTokenNoSigningKey(t *testing.T) {
	ks := &KeyStore{}

	claims := &Claims{
		Issuer:   "https://auth.example.com",
		Subject:  "service-a",
		Audience: "service-b",
		Exp:      time.Now().Add(time.Hour).Unix(),
		Iat:      time.Now().Unix(),
	}

	_, err := ks.SignToken(claims)
	if err == nil {
		t.Fatal("expected error when no signing key is configured")
	}
}

func TestGenerateJTI(t *testing.T) {
	jti1, err := GenerateJTI()
	if err != nil {
		t.Fatalf("generate jti: %v", err)
	}
	jti2, err := GenerateJTI()
	if err != nil {
		t.Fatalf("generate jti: %v", err)
	}

	if jti1 == "" {
		t.Error("jti should not be empty")
	}
	if jti1 == jti2 {
		t.Error("two JTIs should not be equal")
	}
	// Should have UUID-like format with dashes
	if len(strings.Split(jti1, "-")) != 5 {
		t.Errorf("jti should have 5 dash-separated parts, got %q", jti1)
	}
}

func TestNewClaims(t *testing.T) {
	claims, err := NewClaims("https://auth.example.com", "service-a", "service-b", "read", 30*time.Minute)
	if err != nil {
		t.Fatalf("new claims: %v", err)
	}

	if claims.Issuer != "https://auth.example.com" {
		t.Errorf("iss = %q, want https://auth.example.com", claims.Issuer)
	}
	if claims.Subject != "service-a" {
		t.Errorf("sub = %q, want service-a", claims.Subject)
	}
	if claims.Audience != "service-b" {
		t.Errorf("aud = %q, want service-b", claims.Audience)
	}
	if claims.Scope != "read" {
		t.Errorf("scope = %q, want read", claims.Scope)
	}
	if claims.Jti == "" {
		t.Error("jti should not be empty")
	}
	if claims.Iat == 0 {
		t.Error("iat should not be zero")
	}
	if claims.Exp <= claims.Iat {
		t.Error("exp should be after iat")
	}
}

func TestNewClaimsNoScope(t *testing.T) {
	claims, err := NewClaims("https://auth.example.com", "service-a", "service-b", "", 30*time.Minute)
	if err != nil {
		t.Fatalf("new claims: %v", err)
	}
	if claims.Scope != "" {
		t.Errorf("scope = %q, want empty", claims.Scope)
	}
}

func TestScopeOmittedFromJSON(t *testing.T) {
	claims := &Claims{
		Issuer:   "https://auth.example.com",
		Subject:  "service-a",
		Audience: "service-b",
		Exp:      time.Now().Add(time.Hour).Unix(),
		Iat:      time.Now().Unix(),
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), `"scope"`) {
		t.Error("scope should be omitted from JSON when empty")
	}
}
