package web

import (
	"context"
	"net/http"
)

type contextKey string

const usernameKey contextKey = "username"

// requireAuth is middleware that checks for a valid session cookie.
// If the request is not authenticated, it redirects to the login page.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := parseSessionCookie(s.sessionSecret, r)
		if err != nil {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), usernameKey, session.Username)
		next(w, r.WithContext(ctx))
	}
}

// getUsername returns the authenticated username from the request context
func getUsername(r *http.Request) string {
	if v, ok := r.Context().Value(usernameKey).(string); ok {
		return v
	}
	return ""
}
