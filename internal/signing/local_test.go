package signing

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestLocalRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)})
	s, err := ParseLocal(b)
	if err != nil {
		t.Fatal(err)
	}
	if s.Algorithm() != "RS256" || s.KeyID() == "" {
		t.Fatalf("unexpected signer: %s %q", s.Algorithm(), s.KeyID())
	}
	d := sha256.Sum256([]byte("message"))
	sig, err := s.Sign(context.Background(), d[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, 0, d[:], sig); err == nil {
		t.Fatal("verification without hash should fail")
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, s.Hash(), d[:], sig); err != nil {
		t.Fatal(err)
	}
	jwk, err := s.PublicJWK(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if jwk["kid"] != s.KeyID() || jwk["kty"] != "RSA" {
		t.Fatalf("bad jwk: %#v", jwk)
	}
}

func mustPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
