package app

import (
	"context"
	"fmt"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/authn"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/operational"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/signing"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/signing/gcpkms"
)

type SigningBundle struct {
	Active    signing.Signer
	Published []signing.Signer
	Keys      authn.KeyProvider
	close     func() error
}

func (b *SigningBundle) Close() error {
	if b == nil || b.close == nil {
		return nil
	}
	return b.close()
}

func BuildSigning(ctx context.Context, op operational.Config) (*SigningBundle, error) {
	var active signing.Signer
	var closeFn func() error
	var err error
	switch op.SigningProvider {
	case "local":
		active, err = signing.LoadLocal(op.SigningKeyFile)
	case "gcp-kms":
		var kms *gcpkms.Signer
		kms, err = gcpkms.New(ctx, op.GCPKMSKey)
		if kms != nil {
			active = kms
			closeFn = kms.Close
		}
	default:
		return nil, fmt.Errorf("unsupported signing provider %q", op.SigningProvider)
	}
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*SigningBundle, error) {
		if closeFn != nil {
			_ = closeFn()
		}
		return nil, err
	}
	published := make([]signing.Signer, 0, len(op.InactiveSigningKeyFiles))
	for _, path := range op.InactiveSigningKeyFiles {
		value, loadErr := signing.LoadLocal(path)
		if loadErr != nil {
			return fail(fmt.Errorf("load inactive signing key %s: %w", path, loadErr))
		}
		published = append(published, value)
	}
	all := append([]signing.Signer{active}, published...)
	jwks := make([]map[string]any, 0, len(all))
	for _, value := range all {
		jwk, jwkErr := value.PublicJWK(ctx)
		if jwkErr != nil {
			return fail(jwkErr)
		}
		jwks = append(jwks, map[string]any(jwk))
	}
	keys, err := authn.NewStaticJWKs(jwks)
	if err != nil {
		return fail(err)
	}
	if closeFn == nil {
		closeFn = func() error { return nil }
	}
	return &SigningBundle{Active: active, Published: published, Keys: keys, close: closeFn}, nil
}
