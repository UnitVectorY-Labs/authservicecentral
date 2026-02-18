package web

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/jwt"
)

func (s *Server) handleJWTBearerGrant(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	assertion := r.FormValue("assertion")
	audience := r.FormValue("audience")
	scopeParam := r.FormValue("scope")
	requestedScopes := strings.Fields(scopeParam)
	decision := "deny"
	reason := "invalid request"
	var subjectApplicationID *int64
	var audienceApplicationID *int64
	defer s.recordDataPlaneAudit(r, subjectApplicationID, audienceApplicationID, requestedScopes, decision, reason, map[string]interface{}{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"client_id":  clientID,
		"audience":   audience,
	})

	// Validate required parameters
	if clientID == "" {
		reason = "client_id is required"
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "client_id is required")
		return
	}
	if assertion == "" {
		reason = "assertion is required"
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "assertion is required")
		return
	}
	if audience == "" {
		reason = "audience is required"
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "audience is required")
		return
	}

	ctx := r.Context()

	// Look up the subject application by client_id (which is the application subject)
	subjectApp, err := database.LookupApplicationBySubject(ctx, s.db, clientID)
	if err != nil {
		reason = "subject application lookup failed"
		log.Printf("error looking up subject application: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errInvalidClient, "internal error")
		return
	}
	if subjectApp == nil {
		reason = "unknown client_id"
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "unknown client_id")
		return
	}
	if subjectApp.Locked {
		reason = "subject application is locked"
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "subject application is locked")
		return
	}
	subjectApplicationID = int64Ptr(subjectApp.ID)

	// Look up the audience application
	audienceApp, err := database.LookupApplicationBySubject(ctx, s.db, audience)
	if err != nil {
		reason = "audience application lookup failed"
		log.Printf("error looking up audience application: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errInvalidRequest, "internal error")
		return
	}
	if audienceApp == nil {
		reason = "unknown audience"
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "unknown audience")
		return
	}
	if audienceApp.Locked {
		reason = "audience application is locked"
		writeOAuthError(w, http.StatusForbidden, errAccessDenied, "audience application is locked")
		return
	}
	audienceApplicationID = int64Ptr(audienceApp.ID)

	// Check authorization
	auth, err := database.LookupAuthorization(ctx, s.db, subjectApp.ID, audienceApp.ID)
	if err != nil {
		reason = "authorization lookup failed"
		log.Printf("error looking up authorization: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errAccessDenied, "internal error")
		return
	}
	if auth == nil {
		reason = "no authorization exists for this subject and audience"
		writeOAuthError(w, http.StatusForbidden, errAccessDenied, "no authorization exists for this subject and audience")
		return
	}
	if !auth.Enabled {
		reason = "authorization is disabled"
		writeOAuthError(w, http.StatusForbidden, errAccessDenied, "authorization is disabled")
		return
	}

	// Get workloads linked to the subject application
	workloads, err := database.LookupWorkloadsForApplication(ctx, s.db, subjectApp.ID)
	if err != nil {
		reason = "workload lookup failed"
		log.Printf("error looking up workloads: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errInvalidGrant, "internal error")
		return
	}
	if len(workloads) == 0 {
		reason = "no workloads configured for this application"
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "no workloads configured for this application")
		return
	}

	// Parse the assertion JWT without verifying signature
	header, claims, parts, err := parseJWTWithoutVerification(assertion)
	if err != nil {
		reason = "invalid assertion JWT"
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "invalid assertion JWT")
		return
	}

	// Extract claims
	issuer, _ := claims["iss"].(string)
	if issuer == "" {
		reason = "assertion missing iss claim"
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "assertion missing iss claim")
		return
	}

	// Check expiration
	if expVal, ok := claims["exp"]; ok {
		var expTime float64
		switch v := expVal.(type) {
		case float64:
			expTime = v
		case json.Number:
			expTime, _ = v.Float64()
		}
		if time.Now().Unix() > int64(expTime) {
			reason = "assertion has expired"
			writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "assertion has expired")
			return
		}
	}

	// Extract kid from header
	kid, _ := header["kid"].(string)

	// Find a matching workload by issuer
	var matchedWorkload *database.WorkloadWithProvider
	for i := range workloads {
		if workloads[i].IssuerURL == issuer {
			matchedWorkload = &workloads[i]
			break
		}
	}
	if matchedWorkload == nil {
		reason = "no workload matches the assertion issuer"
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "no workload matches the assertion issuer")
		return
	}

	// Verify the workload's provider has a JWKS URL
	if !matchedWorkload.JWKSURL.Valid || matchedWorkload.JWKSURL.String == "" {
		reason = "identity provider has no JWKS URL configured"
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "identity provider has no JWKS URL configured")
		return
	}

	// Fetch the JWK and verify signature
	jwkData, err := s.fetchJWKS(ctx, matchedWorkload.JWKSURL.String, kid)
	if err != nil {
		reason = "unable to fetch signing key"
		log.Printf("error fetching JWKS: %v", err)
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "unable to fetch signing key")
		return
	}
	if jwkData == nil {
		reason = "signing key not found"
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "signing key not found")
		return
	}

	if err := verifyJWTSignature(parts, jwkData); err != nil {
		reason = "assertion signature verification failed"
		log.Printf("JWT signature verification failed: %v", err)
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "assertion signature verification failed")
		return
	}

	// Verify selector claims match
	if !matchSelector(claims, matchedWorkload.Selector) {
		reason = "assertion claims do not match workload selector"
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "assertion claims do not match workload selector")
		return
	}

	// Validate scopes
	var grantedScopes string
	if scopeParam != "" {
		requestedScopes := strings.Fields(scopeParam)

		allowedScopes, err := database.LookupAuthorizedScopes(ctx, s.db, subjectApp.ID, audienceApp.ID)
		if err != nil {
			reason = "scope lookup failed"
			log.Printf("error looking up scopes: %v", err)
			writeOAuthError(w, http.StatusInternalServerError, errInvalidScope, "internal error")
			return
		}

		allowedSet := make(map[string]bool, len(allowedScopes))
		for _, sc := range allowedScopes {
			allowedSet[sc] = true
		}

		for _, sc := range requestedScopes {
			if !allowedSet[sc] {
				reason = "requested scope is not allowed"
				writeOAuthError(w, http.StatusBadRequest, errInvalidScope, "requested scope is not allowed")
				return
			}
		}

		grantedScopes = strings.Join(requestedScopes, " ")
	}

	// Mint the JWT
	tokenClaims, err := jwt.NewClaims(
		s.cfg.JWTIssuer,
		subjectApp.Subject,
		audienceApp.Subject,
		grantedScopes,
		s.cfg.JWTTTL,
	)
	if err != nil {
		reason = "claim creation failed"
		log.Printf("error creating claims: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errInvalidRequest, "internal error")
		return
	}

	token, err := s.keyStore.SignToken(tokenClaims)
	if err != nil {
		reason = "token signing failed"
		log.Printf("error signing token: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errInvalidRequest, "internal error")
		return
	}

	// Build the response
	response := map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(s.cfg.JWTTTL.Seconds()),
	}
	if grantedScopes != "" {
		response["scope"] = grantedScopes
	}

	decision = "allow"
	reason = "token issued"
	writeJSON(w, http.StatusOK, response)
}

// parseJWTWithoutVerification splits a JWT and decodes the header and claims.
// Returns header map, claims map, and the raw parts for signature verification.
func parseJWTWithoutVerification(tokenStr string) (header map[string]interface{}, claims map[string]interface{}, parts []string, err error) {
	parts = strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid JWT header encoding: %w", err)
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid JWT claims encoding: %w", err)
	}

	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid JWT header JSON: %w", err)
	}

	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid JWT claims JSON: %w", err)
	}

	return header, claims, parts, nil
}

// fetchJWKS fetches the JWK for a given kid from a JWKS URL, using the database cache.
func (s *Server) fetchJWKS(ctx context.Context, jwksURL, kid string) (json.RawMessage, error) {
	// Check cache
	entry, err := database.LookupJWKCacheEntry(ctx, s.db, jwksURL, kid)
	if err != nil {
		return nil, fmt.Errorf("cache lookup: %w", err)
	}
	if entry != nil && time.Now().Before(entry.ExpiresAt) {
		if !entry.Found {
			return nil, nil
		}
		return entry.JWK, nil
	}

	// Fetch JWKS from URL
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("read JWKS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	// Find the key with matching kid
	expiresAt := time.Now().Add(1 * time.Hour)
	var matchedKey json.RawMessage
	for _, keyRaw := range jwks.Keys {
		var keyMeta struct {
			KID string `json:"kid"`
		}
		if err := json.Unmarshal(keyRaw, &keyMeta); err != nil {
			continue
		}
		if keyMeta.KID == kid {
			matchedKey = keyRaw
			break
		}
	}

	// Cache the result (positive or negative)
	found := matchedKey != nil
	if err := database.UpsertJWKCacheEntry(ctx, s.db, jwksURL, kid, found, matchedKey, expiresAt); err != nil {
		log.Printf("error caching JWK: %v", err)
	}

	if !found {
		return nil, nil
	}
	return matchedKey, nil
}

// verifyJWTSignature verifies a JWT signature using a JWK.
func verifyJWTSignature(parts []string, jwkData json.RawMessage) error {
	var jwk struct {
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		// RSA fields
		N string `json:"n"`
		E string `json:"e"`
		// ECDSA fields
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(jwkData, &jwk); err != nil {
		return fmt.Errorf("parse JWK: %w", err)
	}

	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	switch jwk.Kty {
	case "RSA":
		return verifyRSASignature(signingInput, sigBytes, jwk.N, jwk.E, jwk.Alg)
	case "EC":
		return verifyECDSASignature(signingInput, sigBytes, jwk.X, jwk.Y, jwk.Crv, jwk.Alg)
	default:
		return fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func verifyRSASignature(signingInput string, sig []byte, nB64, eB64, alg string) error {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return fmt.Errorf("decode RSA n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return fmt.Errorf("decode RSA e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return fmt.Errorf("RSA exponent too large")
	}

	pub := &rsa.PublicKey{N: n, E: int(e.Int64())}

	hashFunc, cryptoHash, err := rsaHashFunc(alg)
	if err != nil {
		return err
	}

	h := hashFunc()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	return rsa.VerifyPKCS1v15(pub, cryptoHash, digest, sig)
}

func verifyECDSASignature(signingInput string, sig []byte, xB64, yB64, crv, alg string) error {
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return fmt.Errorf("decode EC x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return fmt.Errorf("decode EC y: %w", err)
	}

	curve, keySize, err := ecCurve(crv)
	if err != nil {
		return err
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	hashFunc, err := ecHashFunc(alg)
	if err != nil {
		return err
	}

	h := hashFunc()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	// ECDSA signature in JWT is r || s, each of keySize bytes
	if len(sig) != 2*keySize {
		return fmt.Errorf("invalid ECDSA signature length")
	}
	r := new(big.Int).SetBytes(sig[:keySize])
	sVal := new(big.Int).SetBytes(sig[keySize:])

	if !ecdsa.Verify(pub, digest, r, sVal) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

func rsaHashFunc(alg string) (func() hash.Hash, crypto.Hash, error) {
	switch alg {
	case "RS256":
		return sha256.New, crypto.SHA256, nil
	case "RS384":
		return sha512.New384, crypto.SHA384, nil
	case "RS512":
		return sha512.New, crypto.SHA512, nil
	default:
		return nil, 0, fmt.Errorf("unsupported RSA algorithm: %s", alg)
	}
}

func ecCurve(crv string) (elliptic.Curve, int, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), 48, nil
	case "P-521":
		return elliptic.P521(), 66, nil
	default:
		return nil, 0, fmt.Errorf("unsupported EC curve: %s", crv)
	}
}

func ecHashFunc(alg string) (func() hash.Hash, error) {
	switch alg {
	case "ES256":
		return sha256.New, nil
	case "ES384":
		return sha512.New384, nil
	case "ES512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm: %s", alg)
	}
}

// matchSelector checks if JWT claims match the workload selector.
func matchSelector(claims map[string]interface{}, selector json.RawMessage) bool {
	if len(selector) == 0 {
		return true
	}

	var selectorMap map[string]interface{}
	if err := json.Unmarshal(selector, &selectorMap); err != nil {
		return false
	}

	for key, expected := range selectorMap {
		actual, ok := claims[key]
		if !ok {
			return false
		}
		expectedStr := fmt.Sprintf("%v", expected)
		actualStr := fmt.Sprintf("%v", actual)
		if expectedStr != actualStr {
			return false
		}
	}
	return true
}
