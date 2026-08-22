package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type KeyProvider interface {
	Key(ctx context.Context, kid, alg string) (crypto.PublicKey, error)
}

type JWKSet struct {
	Keys []map[string]any `json:"keys"`
}

type StaticKeys struct {
	keys       map[string]crypto.PublicKey
	algorithms map[string]string
}

func NewStaticJWKS(data []byte) (*StaticKeys, error) {
	var set JWKSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	return staticFromJWKs(set.Keys)
}

func NewStaticJWKs(jwks []map[string]any) (*StaticKeys, error) { return staticFromJWKs(jwks) }

func staticFromJWKs(jwks []map[string]any) (*StaticKeys, error) {
	keys := make(map[string]crypto.PublicKey, len(jwks))
	algorithms := make(map[string]string, len(jwks))
	for _, jwk := range jwks {
		kid, _ := jwk["kid"].(string)
		if kid == "" {
			return nil, errors.New("JWK kid is required")
		}
		if _, exists := keys[kid]; exists {
			return nil, fmt.Errorf("duplicate JWK kid %q", kid)
		}
		if use, _ := jwk["use"].(string); use != "" && use != "sig" {
			return nil, fmt.Errorf("JWK %q is not a signing key", kid)
		}
		key, err := parseJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("JWK %q: %w", kid, err)
		}
		keys[kid] = key
		if alg, _ := jwk["alg"].(string); alg != "" {
			algorithms[kid] = alg
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("at least one JWK is required")
	}
	return &StaticKeys{keys: keys, algorithms: algorithms}, nil
}

func NewStaticPEM(kid string, data []byte) (*StaticKeys, error) {
	if kid == "" {
		return nil, errors.New("PEM key kid is required")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("public key is not PEM")
	}
	var key any
	var err error
	if key, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if rsaKey, rsaErr := x509.ParsePKCS1PublicKey(block.Bytes); rsaErr == nil {
			key, err = rsaKey, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	switch key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return nil, errors.New("only RSA and EC public keys are supported")
	}
	return &StaticKeys{keys: map[string]crypto.PublicKey{kid: key}, algorithms: map[string]string{}}, nil
}

func (s *StaticKeys) Key(_ context.Context, kid, alg string) (crypto.PublicKey, error) {
	if kid == "" && len(s.keys) == 1 {
		for _, key := range s.keys {
			return key, nil
		}
	}
	key, ok := s.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	if declared := s.algorithms[kid]; declared != "" && declared != alg {
		return nil, fmt.Errorf("JWK %q is restricted to algorithm %q", kid, declared)
	}
	return key, nil
}

func parseJWK(jwk map[string]any) (crypto.PublicKey, error) {
	decode := func(name string) ([]byte, error) {
		value, ok := jwk[name].(string)
		if !ok || value == "" {
			return nil, fmt.Errorf("missing %s", name)
		}
		b, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("invalid %s", name)
		}
		return b, nil
	}
	switch jwk["kty"] {
	case "RSA":
		n, err := decode("n")
		if err != nil {
			return nil, err
		}
		e, err := decode("e")
		if err != nil {
			return nil, err
		}
		if len(e) == 0 || len(e) > 4 {
			return nil, errors.New("invalid RSA exponent")
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 | int(b)
		}
		if exponent < 3 {
			return nil, errors.New("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}, nil
	case "EC":
		curveName, _ := jwk["crv"].(string)
		var curve elliptic.Curve
		switch curveName {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", curveName)
		}
		xb, err := decode("x")
		if err != nil {
			return nil, err
		}
		yb, err := decode("y")
		if err != nil {
			return nil, err
		}
		x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("EC point is not on curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported kty %q", jwk["kty"])
	}
}

// RemoteKeys obtains keys from an explicit JWKS URL or issuer discovery. It
// honors max-age/Expires and performs at most one forced refresh per Key call
// when a kid is not found.
type RemoteKeys struct {
	Issuer, JWKSURL string
	Discovery       bool
	Client          *http.Client
	DefaultTTL      time.Duration

	mu          sync.Mutex
	keys        map[string]crypto.PublicKey
	algorithms  map[string]string
	expires     time.Time
	resolvedURL string
}

func (r *RemoteKeys) Key(ctx context.Context, kid, alg string) (crypto.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("kid is required for remote JWKS")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if r.keys == nil || !now.Before(r.expires) {
		if err := r.refresh(ctx); err != nil {
			return nil, err
		}
	}
	if key, ok := r.keys[kid]; ok {
		if declared := r.algorithms[kid]; declared != "" && declared != alg {
			return nil, fmt.Errorf("JWK %q is restricted to algorithm %q", kid, declared)
		}
		return key, nil
	}
	// Bounded unknown-kid refresh: exactly one additional network refresh.
	if err := r.refresh(ctx); err != nil {
		return nil, err
	}
	if key, ok := r.keys[kid]; ok {
		if declared := r.algorithms[kid]; declared != "" && declared != alg {
			return nil, fmt.Errorf("JWK %q is restricted to algorithm %q", kid, declared)
		}
		return key, nil
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}

func (r *RemoteKeys) refresh(ctx context.Context) error {
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	uri := r.JWKSURL
	if uri == "" {
		if !r.Discovery {
			return errors.New("remote key provider requires jwks URL or discovery")
		}
		issuer := strings.TrimSuffix(r.Issuer, "/")
		if issuer == "" {
			return errors.New("issuer is required for discovery")
		}
		discoveryURL := issuer + "/.well-known/openid-configuration"
		var metadata struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if _, err := getJSON(ctx, client, discoveryURL, &metadata); err != nil {
			return fmt.Errorf("OIDC discovery: %w", err)
		}
		if metadata.Issuer != r.Issuer {
			return fmt.Errorf("discovered issuer %q does not match configured issuer %q", metadata.Issuer, r.Issuer)
		}
		uri = metadata.JWKSURI
	}
	if err := validateHTTPURL(uri); err != nil {
		return fmt.Errorf("JWKS URL: %w", err)
	}
	var set JWKSet
	resp, err := getJSON(ctx, client, uri, &set)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	static, err := staticFromJWKs(set.Keys)
	if err != nil {
		return err
	}
	r.keys, r.algorithms, r.resolvedURL = static.keys, static.algorithms, uri
	ttl := cacheTTL(resp, time.Now())
	if ttl <= 0 {
		ttl = r.DefaultTTL
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	r.expires = time.Now().Add(ttl)
	return nil
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("scheme must be http or https")
	}
	if u.Host == "" {
		return errors.New("host is required")
	}
	return nil
}

func getJSON(ctx context.Context, client *http.Client, uri string, dst any) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
	if err := dec.Decode(dst); err != nil {
		return nil, err
	}
	return resp, nil
}

func cacheTTL(resp *http.Response, now time.Time) time.Duration {
	for _, directive := range strings.Split(resp.Header.Get("Cache-Control"), ",") {
		parts := strings.SplitN(strings.TrimSpace(directive), "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "max-age") {
			if seconds, err := strconv.Atoi(strings.Trim(parts[1], `"`)); err == nil && seconds >= 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	if expires, err := http.ParseTime(resp.Header.Get("Expires")); err == nil {
		return expires.Sub(now)
	}
	return 0
}
