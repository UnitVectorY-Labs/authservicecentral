package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func generateRSAKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func generateECKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
}

func generateRSAPublicKeyPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	return privPEM, pubPEM
}

func TestParsePrivateKeyRSA(t *testing.T) {
	pem := generateRSAKeyPEM(t)
	key, err := ParsePrivateKey(pem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key.Algorithm != "RS256" {
		t.Errorf("Algorithm = %q, want %q", key.Algorithm, "RS256")
	}
	if key.Kid == "" {
		t.Error("Kid should not be empty")
	}
	if key.PrivateKey == nil {
		t.Error("PrivateKey should not be nil")
	}
	if key.PublicKey == nil {
		t.Error("PublicKey should not be nil")
	}
}

func TestParsePrivateKeyEC(t *testing.T) {
	pem := generateECKeyPEM(t)
	key, err := ParsePrivateKey(pem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key.Algorithm != "ES256" {
		t.Errorf("Algorithm = %q, want %q", key.Algorithm, "ES256")
	}
	if key.Kid == "" {
		t.Error("Kid should not be empty")
	}
}

func TestParsePublicKey(t *testing.T) {
	_, pubPEM := generateRSAPublicKeyPEM(t)
	key, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key.Algorithm != "RS256" {
		t.Errorf("Algorithm = %q, want %q", key.Algorithm, "RS256")
	}
	if key.PrivateKey != nil {
		t.Error("PrivateKey should be nil for public key")
	}
	if key.PublicKey == nil {
		t.Error("PublicKey should not be nil")
	}
}

func TestKidConsistency(t *testing.T) {
	privPEM, pubPEM := generateRSAPublicKeyPEM(t)

	privKey, err := ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	pubKey, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	if privKey.Kid != pubKey.Kid {
		t.Errorf("kid mismatch: private=%q, public=%q", privKey.Kid, pubKey.Kid)
	}
}

func TestJWKPublicRSA(t *testing.T) {
	keyPEM := generateRSAKeyPEM(t)
	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jwk := key.JWKPublic()

	if jwk["kty"] != "RSA" {
		t.Errorf("kty = %v, want RSA", jwk["kty"])
	}
	if jwk["use"] != "sig" {
		t.Errorf("use = %v, want sig", jwk["use"])
	}
	if jwk["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", jwk["alg"])
	}
	if jwk["kid"] != key.Kid {
		t.Errorf("kid = %v, want %v", jwk["kid"], key.Kid)
	}
	if jwk["n"] == nil || jwk["n"] == "" {
		t.Error("n should not be empty")
	}
	if jwk["e"] == nil || jwk["e"] == "" {
		t.Error("e should not be empty")
	}
}

func TestJWKPublicEC(t *testing.T) {
	keyPEM := generateECKeyPEM(t)
	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jwk := key.JWKPublic()

	if jwk["kty"] != "EC" {
		t.Errorf("kty = %v, want EC", jwk["kty"])
	}
	if jwk["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256", jwk["alg"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("crv = %v, want P-256", jwk["crv"])
	}
	if jwk["x"] == nil || jwk["x"] == "" {
		t.Error("x should not be empty")
	}
	if jwk["y"] == nil || jwk["y"] == "" {
		t.Error("y should not be empty")
	}
}

func TestLoadPrivateKeyFile(t *testing.T) {
	keyPEM := generateRSAKeyPEM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	key, err := LoadPrivateKeyFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key.Algorithm != "RS256" {
		t.Errorf("Algorithm = %q, want %q", key.Algorithm, "RS256")
	}
}

func TestLoadPublicKeyFile(t *testing.T) {
	_, pubPEM := generateRSAPublicKeyPEM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(path, pubPEM, 0644); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	key, err := LoadPublicKeyFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key.Algorithm != "RS256" {
		t.Errorf("Algorithm = %q, want %q", key.Algorithm, "RS256")
	}
}

func TestParsePrivateKeyInvalidPEM(t *testing.T) {
	_, err := ParsePrivateKey([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestParsePublicKeyInvalidPEM(t *testing.T) {
	_, err := ParsePublicKey([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestParsePKCS8PrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})

	parsed, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Algorithm != "RS256" {
		t.Errorf("Algorithm = %q, want %q", parsed.Algorithm, "RS256")
	}
}
