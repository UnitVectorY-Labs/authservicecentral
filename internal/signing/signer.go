// Package signing provides the cryptographic boundary used by platform token
// issuance.  Callers never need access to private key material.
package signing

import (
	"context"
	"crypto"
)

// JWK is the public subset of a JSON Web Key.
type JWK map[string]any

// Signer signs an already-computed digest using a configured JWT algorithm.
type Signer interface {
	Sign(context.Context, []byte) ([]byte, error)
	Algorithm() string
	KeyID() string
	PublicJWK(context.Context) (JWK, error)
	Hash() crypto.Hash
}
