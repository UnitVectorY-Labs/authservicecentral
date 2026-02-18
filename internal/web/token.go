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
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "jwt-bearer grant type is not yet supported")
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

	// Validate required parameters
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "client_id is required")
		return
	}
	if clientSecret == "" {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "client_secret is required")
		return
	}
	if audience == "" {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "audience is required")
		return
	}

	ctx := r.Context()

	// Look up the credential by client_id
	cred, err := database.LookupCredentialByClientID(ctx, s.db, clientID)
	if err != nil {
		log.Printf("error looking up credential: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errInvalidClient, "internal error")
		return
	}
	if cred == nil {
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "invalid client credentials")
		return
	}

	// Check if credential is disabled
	if cred.DisabledAt.Valid {
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "client credential is disabled")
		return
	}

	// Verify the client secret
	if !credential.VerifySecret(clientSecret, cred.SecretHash) {
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "invalid client credentials")
		return
	}

	// Look up the subject application
	subjectApp, err := database.LookupApplicationByID(ctx, s.db, cred.ApplicationID)
	if err != nil {
		log.Printf("error looking up subject application: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errInvalidClient, "internal error")
		return
	}
	if subjectApp == nil || subjectApp.Locked {
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "subject application is unavailable")
		return
	}

	// Look up the audience application
	audienceApp, err := database.LookupApplicationBySubject(ctx, s.db, audience)
	if err != nil {
		log.Printf("error looking up audience application: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errInvalidRequest, "internal error")
		return
	}
	if audienceApp == nil {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "unknown audience")
		return
	}
	if audienceApp.Locked {
		writeOAuthError(w, http.StatusForbidden, errAccessDenied, "audience application is locked")
		return
	}

	// Check authorization
	auth, err := database.LookupAuthorization(ctx, s.db, subjectApp.ID, audienceApp.ID)
	if err != nil {
		log.Printf("error looking up authorization: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errAccessDenied, "internal error")
		return
	}
	if auth == nil {
		writeOAuthError(w, http.StatusForbidden, errAccessDenied, "no authorization exists for this subject and audience")
		return
	}
	if !auth.Enabled {
		writeOAuthError(w, http.StatusForbidden, errAccessDenied, "authorization is disabled")
		return
	}

	// Validate scopes
	var grantedScopes string
	if scopeParam != "" {
		requestedScopes := strings.Fields(scopeParam)

		allowedScopes, err := database.LookupAuthorizedScopes(ctx, s.db, subjectApp.ID, audienceApp.ID)
		if err != nil {
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
				writeOAuthError(w, http.StatusBadRequest, errInvalidScope, "scope '"+sc+"' is not allowed")
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
		log.Printf("error creating claims: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, errInvalidRequest, "internal error")
		return
	}

	token, err := s.keyStore.SignToken(claims)
	if err != nil {
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

	writeJSON(w, http.StatusOK, response)
}
