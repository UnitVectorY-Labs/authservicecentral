package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

// Key represents a loaded key with its computed kid
type Key struct {
	Kid        string
	Algorithm  string
	PrivateKey crypto.PrivateKey // nil for verify-only keys
	PublicKey  crypto.PublicKey
}

// LoadPrivateKeyFile reads a PEM-encoded private key file
func LoadPrivateKeyFile(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}
	return ParsePrivateKey(data)
}

// ParsePrivateKey parses a PEM-encoded private key
func ParsePrivateKey(data []byte) (*Key, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey
	var alg string

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA private key: %w", err)
		}
		privKey = key
		pubKey = &key.PublicKey
		alg = "RS256"
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		privKey = key
		pubKey = &key.PublicKey
		alg = ecAlgorithm(key.Curve)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			privKey = k
			pubKey = &k.PublicKey
			alg = "RS256"
		case *ecdsa.PrivateKey:
			privKey = k
			pubKey = &k.PublicKey
			alg = ecAlgorithm(k.Curve)
		default:
			return nil, fmt.Errorf("unsupported PKCS8 key type: %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	kid, err := computeKid(pubKey)
	if err != nil {
		return nil, err
	}

	return &Key{
		Kid:        kid,
		Algorithm:  alg,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// LoadPublicKeyFile reads a PEM-encoded public key file
func LoadPublicKeyFile(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}
	return ParsePublicKey(data)
}

// ParsePublicKey parses a PEM-encoded public key
func ParsePublicKey(data []byte) (*Key, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	var pubKey crypto.PublicKey
	var alg string

	switch k := key.(type) {
	case *rsa.PublicKey:
		pubKey = k
		alg = "RS256"
	case *ecdsa.PublicKey:
		pubKey = k
		alg = ecAlgorithm(k.Curve)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", key)
	}

	kid, err := computeKid(pubKey)
	if err != nil {
		return nil, err
	}

	return &Key{
		Kid:       kid,
		Algorithm: alg,
		PublicKey: pubKey,
	}, nil
}

// JWKPublic returns the JWK representation of the public key
func (k *Key) JWKPublic() map[string]interface{} {
	jwk := map[string]interface{}{
		"kty": "",
		"use": "sig",
		"kid": k.Kid,
		"alg": k.Algorithm,
	}

	switch pub := k.PublicKey.(type) {
	case *rsa.PublicKey:
		jwk["kty"] = "RSA"
		jwk["n"] = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		jwk["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		jwk["kty"] = "EC"
		jwk["crv"] = pub.Curve.Params().Name
		byteLen := (pub.Curve.Params().BitSize + 7) / 8
		x := pub.X.Bytes()
		y := pub.Y.Bytes()
		// Pad to correct length
		xPadded := make([]byte, byteLen)
		yPadded := make([]byte, byteLen)
		copy(xPadded[byteLen-len(x):], x)
		copy(yPadded[byteLen-len(y):], y)
		jwk["x"] = base64.RawURLEncoding.EncodeToString(xPadded)
		jwk["y"] = base64.RawURLEncoding.EncodeToString(yPadded)
	}

	return jwk
}

// computeKid derives a key ID from the SHA-256 hash of the public key DER encoding
func computeKid(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:])[:16], nil
}

func ecAlgorithm(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "ES256"
	case elliptic.P384():
		return "ES384"
	case elliptic.P521():
		return "ES512"
	default:
		return "ES256"
	}
}
