package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
)

func TestBuildValidatorStaticPEM(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	cfg := &config.Config{Version: 1, TokenSources: map[string]config.TokenSource{"test": {Issuer: "https://issuer.example", Keys: config.Keys{PublicKey: public}, Algorithms: []string{"RS256"}, Identity: config.Identity{SubjectClaim: "sub", Prefix: "test"}}}, Permissions: map[string]config.Permission{"api.invoke": {Resources: []string{"audience"}}}, Roles: map[string]config.Role{"caller": {Permissions: []string{"api.invoke"}}}, Resources: map[string]config.Resource{}}
	if _, err := BuildValidator(cfg, nil); err != nil {
		t.Fatal(err)
	}
}
