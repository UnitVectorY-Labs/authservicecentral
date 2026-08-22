package gcpkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const keyName = "projects/test/locations/global/keyRings/ring/cryptoKeys/signing/cryptoKeyVersions/1"

type fakeClient struct {
	key                                            crypto.Signer
	algorithm                                      kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	state                                          kmspb.CryptoKeyVersion_CryptoKeyVersionState
	name                                           string
	publicCalls, signCalls, closeCalls             int
	getVersionErr, getPublicErr, signErr, closeErr error
	mutatePublic                                   func(*kmspb.PublicKey)
	mutateSignature                                func(*kmspb.AsymmetricSignResponse)
}

func (f *fakeClient) GetCryptoKeyVersion(_ context.Context, _ *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if f.getVersionErr != nil {
		return nil, f.getVersionErr
	}
	return &kmspb.CryptoKeyVersion{Name: f.name, State: f.state, Algorithm: f.algorithm}, nil
}
func (f *fakeClient) GetPublicKey(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	f.publicCalls++
	if f.getPublicErr != nil {
		return nil, f.getPublicErr
	}
	der, _ := x509.MarshalPKIXPublicKey(f.key.Public())
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	response := &kmspb.PublicKey{Name: f.name, Algorithm: f.algorithm, Pem: string(pemBytes), PemCrc32C: wrapperspb.Int64(int64(crc32c(pemBytes)))}
	if f.mutatePublic != nil {
		f.mutatePublic(response)
	}
	return response, nil
}
func (f *fakeClient) AsymmetricSign(_ context.Context, request *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	f.signCalls++
	if f.signErr != nil {
		return nil, f.signErr
	}
	digest := request.GetDigest().GetSha256()
	if got, want := uint32(request.GetDigestCrc32C().GetValue()), crc32c(digest); got != want {
		return nil, errors.New("request checksum mismatch")
	}
	var signature []byte
	var err error
	switch key := f.key.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, key, digest)
		if err == nil {
			signature, err = asn1.Marshal(struct{ R, S *big.Int }{r, s})
		}
	}
	if err != nil {
		return nil, err
	}
	response := &kmspb.AsymmetricSignResponse{Name: f.name, Signature: signature, VerifiedDigestCrc32C: true, SignatureCrc32C: wrapperspb.Int64(int64(crc32c(signature)))}
	if f.mutateSignature != nil {
		f.mutateSignature(response)
	}
	return response, nil
}
func (f *fakeClient) Close() error { f.closeCalls++; return f.closeErr }

func rsaFake(t *testing.T) *fakeClient {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeClient{key: key, name: keyName, state: kmspb.CryptoKeyVersion_ENABLED, algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256}
}
func ecFake(t *testing.T) *fakeClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeClient{key: key, name: keyName, state: kmspb.CryptoKeyVersion_ENABLED, algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256}
}

func TestRSA(t *testing.T) {
	fake := rsaFake(t)
	signer, err := NewWithClient(context.Background(), keyName, fake)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Algorithm() != "RS256" || signer.Hash() != crypto.SHA256 || signer.KeyID() == "" {
		t.Fatalf("unexpected metadata: %s %v %q", signer.Algorithm(), signer.Hash(), signer.KeyID())
	}
	digest := sha256.Sum256([]byte("message"))
	signature, err := signer.Sign(context.Background(), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&fake.key.(*rsa.PrivateKey).PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal(err)
	}
	jwk, err := signer.PublicJWK(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if jwk["kty"] != "RSA" || jwk["alg"] != "RS256" || jwk["kid"] != signer.KeyID() {
		t.Fatalf("jwk=%#v", jwk)
	}
	der, _ := x509.MarshalPKIXPublicKey(fake.key.Public())
	expected := sha256.Sum256(der)
	if signer.KeyID() != base64.RawURLEncoding.EncodeToString(expected[:]) {
		t.Fatal("kid does not derive from DER public key")
	}
	if fake.publicCalls != 1 {
		t.Fatalf("public key calls=%d", fake.publicCalls)
	}
}

func TestECDSAConvertsDERToJWTRaw(t *testing.T) {
	fake := ecFake(t)
	signer, err := NewWithClient(context.Background(), keyName, fake)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("message"))
	signature, err := signer.Sign(context.Background(), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != 64 {
		t.Fatalf("signature length=%d", len(signature))
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(&fake.key.(*ecdsa.PrivateKey).PublicKey, digest[:], r, s) {
		t.Fatal("raw JWT signature did not verify")
	}
	jwk, _ := signer.PublicJWK(context.Background())
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["alg"] != "ES256" {
		t.Fatalf("jwk=%#v", jwk)
	}
}

func TestPublicJWKReturnsCopy(t *testing.T) {
	fake := rsaFake(t)
	signer, err := NewWithClient(context.Background(), keyName, fake)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := signer.PublicJWK(context.Background())
	first["kid"] = "changed"
	second, _ := signer.PublicJWK(context.Background())
	if second["kid"] != signer.KeyID() {
		t.Fatal("cached JWK was mutated")
	}
	if fake.publicCalls != 1 {
		t.Fatalf("public calls=%d", fake.publicCalls)
	}
}

func TestInitializationErrorsCloseClient(t *testing.T) {
	tests := map[string]struct {
		mutate func(*fakeClient)
		want   string
	}{
		"disabled":              {func(f *fakeClient) { f.state = kmspb.CryptoKeyVersion_DISABLED }, "not enabled"},
		"unsupported algorithm": {func(f *fakeClient) { f.algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256 }, "unsupported"},
		"public checksum":       {func(f *fakeClient) { f.mutatePublic = func(p *kmspb.PublicKey) { p.PemCrc32C = wrapperspb.Int64(1) } }, "checksum mismatch"},
		"algorithm mismatch": {func(f *fakeClient) {
			f.mutatePublic = func(p *kmspb.PublicKey) { p.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 }
		}, "does not match"},
		"RSA size mismatch": {func(f *fakeClient) { f.algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256 }, "algorithm requires 4096"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := rsaFake(t)
			tc.mutate(fake)
			_, err := NewWithClient(context.Background(), keyName, fake)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want=%q", err, tc.want)
			}
			if fake.closeCalls != 1 {
				t.Fatalf("close calls=%d", fake.closeCalls)
			}
		})
	}
}

func TestSignErrors(t *testing.T) {
	t.Run("digest length", func(t *testing.T) {
		fake := rsaFake(t)
		signer, _ := NewWithClient(context.Background(), keyName, fake)
		if _, err := signer.Sign(context.Background(), []byte("short")); err == nil {
			t.Fatal("expected error")
		}
		if fake.signCalls != 0 {
			t.Fatal("KMS called for invalid digest")
		}
	})
	t.Run("response checksum", func(t *testing.T) {
		fake := rsaFake(t)
		fake.mutateSignature = func(r *kmspb.AsymmetricSignResponse) { r.SignatureCrc32C = wrapperspb.Int64(1) }
		signer, _ := NewWithClient(context.Background(), keyName, fake)
		digest := sha256.Sum256(nil)
		if _, err := signer.Sign(context.Background(), digest[:]); err == nil || !strings.Contains(err.Error(), "checksum") {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("unverified digest", func(t *testing.T) {
		fake := rsaFake(t)
		fake.mutateSignature = func(r *kmspb.AsymmetricSignResponse) { r.VerifiedDigestCrc32C = false }
		signer, _ := NewWithClient(context.Background(), keyName, fake)
		digest := sha256.Sum256(nil)
		if _, err := signer.Sign(context.Background(), digest[:]); err == nil || !strings.Contains(err.Error(), "did not verify") {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("malformed EC", func(t *testing.T) {
		fake := ecFake(t)
		fake.mutateSignature = func(r *kmspb.AsymmetricSignResponse) {
			r.Signature = []byte("not DER")
			r.SignatureCrc32C = wrapperspb.Int64(int64(crc32c(r.Signature)))
		}
		signer, _ := NewWithClient(context.Background(), keyName, fake)
		digest := sha256.Sum256(nil)
		if _, err := signer.Sign(context.Background(), digest[:]); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestCloseIsIdempotent(t *testing.T) {
	fake := rsaFake(t)
	signer, err := NewWithClient(context.Background(), keyName, fake)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := signer.Close(); err != nil {
		t.Fatal(err)
	}
	if fake.closeCalls != 1 {
		t.Fatalf("close calls=%d", fake.closeCalls)
	}
	digest := sha256.Sum256(nil)
	if _, err := signer.Sign(context.Background(), digest[:]); !errors.Is(err, ErrClosed) {
		t.Fatalf("error=%v", err)
	}
	if _, err := signer.PublicJWK(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("error=%v", err)
	}
}
