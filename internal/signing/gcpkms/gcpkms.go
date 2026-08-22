// Package gcpkms implements platform JWT signing with asymmetric keys whose
// private material remains inside Google Cloud KMS.
package gcpkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"sync"
	"sync/atomic"

	cloudkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/signing"
)

var ErrClosed = errors.New("GCP KMS signer is closed")

// Client is the subset of the official KMS client used by Signer. A Client
// passed to NewWithClient is owned by the returned signer and closed with it.
type Client interface {
	GetCryptoKeyVersion(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	Close() error
}

type Signer struct {
	client   Client
	name     string
	public   crypto.PublicKey
	alg      string
	kid      string
	jwk      signing.JWK
	closed   atomic.Bool
	ops      sync.RWMutex
	close    sync.Once
	closeErr error
}

var _ signing.Signer = (*Signer)(nil)

// New creates a signer using Application Default Credentials.
func New(ctx context.Context, keyVersion string) (*Signer, error) {
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create GCP KMS client: %w", err)
	}
	return NewWithClient(ctx, keyVersion, client)
}

func NewWithClient(ctx context.Context, keyVersion string, client Client) (*Signer, error) {
	if client == nil {
		return nil, errors.New("initialize GCP KMS signer: client is required")
	}
	if keyVersion == "" {
		_ = client.Close()
		return nil, errors.New("initialize GCP KMS signer: key version resource name is required")
	}
	s := &Signer{client: client, name: keyVersion}
	if err := s.initialize(ctx); err != nil {
		_ = client.Close()
		return nil, err
	}
	return s, nil
}

func (s *Signer) initialize(ctx context.Context) error {
	version, err := s.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: s.name})
	if err != nil {
		return fmt.Errorf("get GCP KMS key version: %w", err)
	}
	if version.GetName() != s.name {
		return fmt.Errorf("GCP KMS returned key version %q, expected %q", version.GetName(), s.name)
	}
	if version.GetState() != kmspb.CryptoKeyVersion_ENABLED {
		return fmt.Errorf("GCP KMS key version is not enabled: %s", version.GetState())
	}
	alg, err := jwtAlgorithm(version.GetAlgorithm())
	if err != nil {
		return err
	}
	response, err := s.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: s.name})
	if err != nil {
		return fmt.Errorf("get GCP KMS public key: %w", err)
	}
	if response.GetName() != s.name {
		return fmt.Errorf("GCP KMS returned public key for %q, expected %q", response.GetName(), s.name)
	}
	if response.GetAlgorithm() != version.GetAlgorithm() {
		return fmt.Errorf("GCP KMS public key algorithm %s does not match key version algorithm %s", response.GetAlgorithm(), version.GetAlgorithm())
	}
	if checksum := response.GetPemCrc32C(); checksum != nil && uint32(checksum.GetValue()) != crc32c([]byte(response.GetPem())) {
		return errors.New("GCP KMS public key checksum mismatch")
	}
	block, rest := pem.Decode([]byte(response.GetPem()))
	if block == nil || len(rest) != 0 {
		return errors.New("GCP KMS public key is not a single PEM block")
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse GCP KMS public key: %w", err)
	}
	if err := validatePublicKey(public, version.GetAlgorithm()); err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return fmt.Errorf("marshal GCP KMS public key: %w", err)
	}
	digest := sha256.Sum256(der)
	kid := base64.RawURLEncoding.EncodeToString(digest[:])
	jwk, err := publicJWK(public, alg, kid)
	if err != nil {
		return err
	}
	s.public, s.alg, s.kid, s.jwk = public, alg, kid, jwk
	return nil
}

func (s *Signer) Algorithm() string { return s.alg }
func (s *Signer) KeyID() string     { return s.kid }
func (s *Signer) Hash() crypto.Hash { return crypto.SHA256 }

func (s *Signer) PublicJWK(_ context.Context) (signing.JWK, error) {
	s.ops.RLock()
	defer s.ops.RUnlock()
	if s.closed.Load() {
		return nil, ErrClosed
	}
	out := make(signing.JWK, len(s.jwk))
	for k, v := range s.jwk {
		out[k] = v
	}
	return out, nil
}

func (s *Signer) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	s.ops.RLock()
	defer s.ops.RUnlock()
	if s.closed.Load() {
		return nil, ErrClosed
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("GCP KMS signing requires a %d-byte SHA-256 digest", sha256.Size)
	}
	response, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: s.name, Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}}, DigestCrc32C: wrapperspb.Int64(int64(crc32c(digest)))})
	if err != nil {
		return nil, fmt.Errorf("GCP KMS asymmetric sign: %w", err)
	}
	if response.GetName() != s.name {
		return nil, fmt.Errorf("GCP KMS signed with key %q, expected %q", response.GetName(), s.name)
	}
	if !response.GetVerifiedDigestCrc32C() {
		return nil, errors.New("GCP KMS did not verify the digest checksum")
	}
	if response.GetSignatureCrc32C() == nil || uint32(response.GetSignatureCrc32C().GetValue()) != crc32c(response.GetSignature()) {
		return nil, errors.New("GCP KMS signature checksum mismatch")
	}
	switch key := s.public.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, response.GetSignature()); err != nil {
			return nil, fmt.Errorf("verify GCP KMS RSA signature: %w", err)
		}
		return append([]byte(nil), response.GetSignature()...), nil
	case *ecdsa.PublicKey:
		var signature struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(response.GetSignature(), &signature)
		if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
			return nil, errors.New("GCP KMS returned malformed ECDSA signature")
		}
		if signature.R.Sign() <= 0 || signature.S.Sign() <= 0 || !ecdsa.Verify(key, digest, signature.R, signature.S) {
			return nil, errors.New("GCP KMS returned invalid ECDSA signature")
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		if signature.R.BitLen() > size*8 || signature.S.BitLen() > size*8 {
			return nil, errors.New("GCP KMS returned oversized ECDSA signature")
		}
		out := make([]byte, size*2)
		signature.R.FillBytes(out[:size])
		signature.S.FillBytes(out[size:])
		return out, nil
	default:
		return nil, errors.New("unsupported cached GCP KMS public key")
	}
}

func (s *Signer) Close() error {
	if s == nil {
		return nil
	}
	s.close.Do(func() {
		s.ops.Lock()
		defer s.ops.Unlock()
		s.closed.Store(true)
		s.closeErr = s.client.Close()
	})
	return s.closeErr
}

func jwtAlgorithm(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (string, error) {
	switch algorithm {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		return "RS256", nil
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		return "ES256", nil
	default:
		return "", fmt.Errorf("unsupported GCP KMS signing algorithm: %s", algorithm)
	}
}

func validatePublicKey(public crypto.PublicKey, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) error {
	alg, err := jwtAlgorithm(algorithm)
	if err != nil {
		return err
	}
	switch key := public.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" {
			return fmt.Errorf("GCP KMS algorithm %s does not match RSA public key", alg)
		}
		expectedBits := map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]int{
			kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256: 2048,
			kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256: 3072,
			kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256: 4096,
		}[algorithm]
		if key.N.BitLen() != expectedBits {
			return fmt.Errorf("GCP KMS RSA public key is %d bits, algorithm requires %d", key.N.BitLen(), expectedBits)
		}
	case *ecdsa.PublicKey:
		if alg != "ES256" || key.Curve != elliptic.P256() {
			return errors.New("GCP KMS ES256 key must use the P-256 curve")
		}
	default:
		return fmt.Errorf("unsupported GCP KMS public key type %T", public)
	}
	return nil
}

func publicJWK(public crypto.PublicKey, alg, kid string) (signing.JWK, error) {
	enc := base64.RawURLEncoding.EncodeToString
	switch key := public.(type) {
	case *rsa.PublicKey:
		return signing.JWK{"kty": "RSA", "use": "sig", "alg": alg, "kid": kid, "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}, nil
	case *ecdsa.PublicKey:
		size := (key.Curve.Params().BitSize + 7) / 8
		x, y := make([]byte, size), make([]byte, size)
		key.X.FillBytes(x)
		key.Y.FillBytes(y)
		return signing.JWK{"kty": "EC", "use": "sig", "alg": alg, "kid": kid, "crv": "P-256", "x": enc(x), "y": enc(y)}, nil
	default:
		return nil, fmt.Errorf("unsupported GCP KMS public key type %T", public)
	}
}

var crcTable = crc32.MakeTable(crc32.Castagnoli)

func crc32c(data []byte) uint32 { return crc32.Checksum(data, crcTable) }
