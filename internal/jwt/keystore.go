package jwt

import (
	"fmt"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
)

// KeyStore holds the loaded signing and verification keys
type KeyStore struct {
	SigningKey   *Key   // active signing key (private)
	AllKeys     []*Key // all keys for JWKS endpoint
}

// LoadKeyStore loads all keys from the configuration
func LoadKeyStore(cfg *config.Config) (*KeyStore, error) {
	ks := &KeyStore{}

	// Load the active signing key
	if cfg.JWTSigningKeyFile != "" {
		key, err := LoadPrivateKeyFile(cfg.JWTSigningKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load signing key: %w", err)
		}
		ks.SigningKey = key
		ks.AllKeys = append(ks.AllKeys, key)
	}

	// Load inactive signing keys (private keys no longer used for signing but still in JWKS)
	for _, path := range cfg.JWTInactiveSigningKeyFiles {
		if path == "" {
			continue
		}
		key, err := LoadPrivateKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("load inactive signing key %s: %w", path, err)
		}
		key.PrivateKey = nil // clear private key; only used for JWKS
		ks.AllKeys = append(ks.AllKeys, key)
	}

	// Load verify-only public keys
	for _, path := range cfg.JWTVerifyKeyFiles {
		if path == "" {
			continue
		}
		key, err := LoadPublicKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("load verify key %s: %w", path, err)
		}
		ks.AllKeys = append(ks.AllKeys, key)
	}

	return ks, nil
}

// JWKS returns the JSON Web Key Set representation
func (ks *KeyStore) JWKS() map[string]interface{} {
	keys := make([]map[string]interface{}, 0, len(ks.AllKeys))
	for _, k := range ks.AllKeys {
		keys = append(keys, k.JWKPublic())
	}
	return map[string]interface{}{
		"keys": keys,
	}
}
