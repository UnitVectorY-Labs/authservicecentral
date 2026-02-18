package web

import (
	"log"
	"net/http"
	"strings"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/credential"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/jwt"
)

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "malformed request body")
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "client_credentials":
		s.handleClientCredentialsGrant(w, r)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		s.handleJWTBearerGrant(w, r)
	case "":
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "grant_type is required")
	default:
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "unsupported grant_type")
	}
}

func (s *Server) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	audience := r.FormValue("audience")
	scopeParam := r.FormValue("scope")
	requestedScopes := strings.Fields(scopeParam)
	decision := "deny"
	reason := "invalid request"
	var subjectApplicationID *int64
	var audienceApplicationID *int64
	defer s.recordDataPlaneAudit(r, subjectApplicationID, audienceApplicationID, requestedScopes, decision, reason, map[string]interface{}{
		"grant_type": "client_credentials",
		"client_id":  clientID,
		"audience":   audience,
	})

	// Validate required parameters
	if clientID == "" {
		reason = "client_id is required"
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "client_id is required")
		return
	}
	if clientSecret == "" {
		reason = "client_secret is required"
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "client_secret is required")
		return
	}
	if len(clientSecret) > 1024 {
		reason = "client_secret exceeds maximum length"
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "client_secret exceeds maximum length")
		return
	}
	if audience == "" {
		reason = "audience is required"
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "audience is required")
		return
	}

	ctx := r.Context()

	// Look up the credential by client_id
	cred, err := database.LookupCredentialByClientID(ctx, s.db, clientID)
	if err != nil {
		reason = "credential lookup failed"
		log.Printf("error looking up credential: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errInvalidClient, "internal error")
		return
	}
	if cred == nil {
		reason = "invalid client credentials"
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "invalid client credentials")
		return
	}
	subjectApplicationID = int64Ptr(cred.ApplicationID)

	// Check if credential is disabled
	if cred.DisabledAt.Valid {
		reason = "client credential is disabled"
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "client credential is disabled")
		return
	}

	// Verify the client secret
	if !credential.VerifySecret(clientSecret, cred.SecretHash) {
		reason = "invalid client credentials"
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "invalid client credentials")
		return
	}

	// Look up the subject application
	subjectApp, err := database.LookupApplicationByID(ctx, s.db, cred.ApplicationID)
	if err != nil {
		reason = "subject application lookup failed"
		log.Printf("error looking up subject application: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errInvalidClient, "internal error")
		return
	}
	if subjectApp == nil || subjectApp.Locked {
		reason = "subject application is unavailable"
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "subject application is unavailable")
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
	claims, err := jwt.NewClaims(
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

	token, err := s.keyStore.SignToken(claims)
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
