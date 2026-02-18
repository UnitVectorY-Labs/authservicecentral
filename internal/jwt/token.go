package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// Claims represents the JWT claims for a minted access token
type Claims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Jti      string `json:"jti,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

// SignToken creates a signed JWT using the active signing key
func (ks *KeyStore) SignToken(claims *Claims) (string, error) {
	if ks.SigningKey == nil {
		return "", fmt.Errorf("no signing key configured")
	}

	key := ks.SigningKey

	header := map[string]string{
		"alg": key.Algorithm,
		"typ": "JWT",
		"kid": key.Kid,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	signature, err := sign([]byte(signingInput), key.PrivateKey, key.Algorithm)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + signatureB64, nil
}

// GenerateJTI creates a random token identifier
func GenerateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// NewClaims creates claims for a new access token
func NewClaims(issuer, subject, audience, scope string, ttl time.Duration) (*Claims, error) {
	jti, err := GenerateJTI()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	claims := &Claims{
		Issuer:   issuer,
		Subject:  subject,
		Audience: audience,
		Exp:      now.Add(ttl).Unix(),
		Iat:      now.Unix(),
		Jti:      jti,
	}
	if scope != "" {
		claims.Scope = scope
	}
	return claims, nil
}

func sign(input []byte, privateKey crypto.PrivateKey, alg string) ([]byte, error) {
	var hashFunc crypto.Hash
	switch alg {
	case "RS256", "ES256":
		hashFunc = crypto.SHA256
	case "ES384":
		hashFunc = crypto.SHA384
	case "ES512", "RS512":
		hashFunc = crypto.SHA512
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	h := hashFunc.New()
	h.Write(input)
	digest := h.Sum(nil)

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, hashFunc, digest)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return nil, fmt.Errorf("ecdsa sign: %w", err)
		}
		// Encode r and s as fixed-size big-endian byte arrays
		byteLen := ecKeySize(k.Curve)
		sig := make([]byte, 2*byteLen)
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(sig[byteLen-len(rBytes):byteLen], rBytes)
		copy(sig[2*byteLen-len(sBytes):], sBytes)
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", privateKey)
	}
}

func ecKeySize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

// VerifyTokenSignature verifies a JWT signature using the provided public key (for testing)
func VerifyTokenSignature(token string, pubKey crypto.PublicKey, alg string) error {
	parts := splitToken(token)
	if parts == nil {
		return fmt.Errorf("invalid token format")
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	var hashFunc crypto.Hash
	switch alg {
	case "RS256", "ES256":
		hashFunc = crypto.SHA256
	case "ES384":
		hashFunc = crypto.SHA384
	case "ES512":
		hashFunc = crypto.SHA512
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}

	h := hashFunc.New()
	h.Write(signingInput)
	digest := h.Sum(nil)

	switch k := pubKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, hashFunc, digest, signature)
	case *ecdsa.PublicKey:
		byteLen := ecKeySize(k.Curve)
		if len(signature) != 2*byteLen {
			return fmt.Errorf("invalid signature length")
		}
		r := new(big.Int).SetBytes(signature[:byteLen])
		s := new(big.Int).SetBytes(signature[byteLen:])
		if !ecdsa.Verify(k, digest, r, s) {
			return fmt.Errorf("ecdsa verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type: %T", pubKey)
	}
}

func splitToken(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		return nil
	}
	return parts
}
