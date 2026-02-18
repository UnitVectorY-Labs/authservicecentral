package web

import (
	"encoding/json"
	"net/http"
)

// OAuth 2.0 error codes per RFC 6749
const (
	errInvalidRequest     = "invalid_request"
	errInvalidClient      = "invalid_client"
	errInvalidGrant       = "invalid_grant"
	errUnauthorizedClient = "unauthorized_client"
	errAccessDenied       = "access_denied"
	errInvalidScope       = "invalid_scope"
)

type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeOAuthError(w http.ResponseWriter, statusCode int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(oauthError{
		Error:            errorCode,
		ErrorDescription: description,
	})
}
