package signing

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
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

type Local struct {
	key crypto.Signer
	alg string
	kid string
}

func LoadLocal(path string) (*Local, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	return ParseLocal(b)
}

func ParseLocal(b []byte) (*Local, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("signing key is not PEM")
	}
	var key any
	var err error
	if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes); rsaErr == nil {
			key, err = rsaKey, nil
		} else if ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			key, err = ecKey, nil
		}
	}
	signer, ok := key.(crypto.Signer)
	if err != nil || !ok {
		return nil, errors.New("unsupported private signing key")
	}
	alg := ""
	switch k := signer.Public().(type) {
	case *rsa.PublicKey:
		alg = "RS256"
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("only P-256 ECDSA keys are supported")
		}
		alg = "ES256"
	default:
		return nil, errors.New("only RSA and P-256 ECDSA keys are supported")
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	digest := sha256.Sum256(der)
	return &Local{key: signer, alg: alg, kid: base64.RawURLEncoding.EncodeToString(digest[:])}, nil
}

func (l *Local) Algorithm() string { return l.alg }
func (l *Local) KeyID() string     { return l.kid }
func (l *Local) Hash() crypto.Hash { return crypto.SHA256 }

func (l *Local) Sign(_ context.Context, digest []byte) ([]byte, error) {
	switch key := l.key.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		out := make([]byte, size*2)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out, nil
	default:
		return nil, errors.New("unsupported key")
	}
}

func (l *Local) PublicJWK(_ context.Context) (JWK, error) {
	enc := base64.RawURLEncoding.EncodeToString
	switch key := l.key.Public().(type) {
	case *rsa.PublicKey:
		e := big.NewInt(int64(key.E)).Bytes()
		return JWK{"kty": "RSA", "use": "sig", "alg": l.alg, "kid": l.kid, "n": enc(key.N.Bytes()), "e": enc(e)}, nil
	case *ecdsa.PublicKey:
		size := (key.Curve.Params().BitSize + 7) / 8
		x, y := make([]byte, size), make([]byte, size)
		key.X.FillBytes(x)
		key.Y.FillBytes(y)
		return JWK{"kty": "EC", "use": "sig", "alg": l.alg, "kid": l.kid, "crv": "P-256", "x": enc(x), "y": enc(y)}, nil
	default:
		return nil, errors.New("unsupported key")
	}
}
