package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	sessionCookieName = "asc_session"
	sessionMaxAge     = 8 * time.Hour
)

// sessionData holds the session state encoded in the cookie
type sessionData struct {
	Username  string
	ExpiresAt time.Time
}

// generateSessionSecret creates a random 32-byte secret for signing cookies
func generateSessionSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate session secret: %w", err)
	}
	return secret, nil
}

// createSessionCookie creates a signed session cookie for the given username
func createSessionCookie(secret []byte, username string) *http.Cookie {
	expires := time.Now().Add(sessionMaxAge)
	payload := fmt.Sprintf("%s|%d", username, expires.Unix())
	sig := signPayload(secret, payload)

	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(payload + "|" + sig)),
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionMaxAge.Seconds()),
	}
}

// parseSessionCookie validates and parses a session cookie
func parseSessionCookie(secret []byte, r *http.Request) (*sessionData, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("no session cookie")
	}

	raw, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid cookie encoding")
	}

	parts := strings.SplitN(string(raw), "|", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid cookie format")
	}

	username := parts[0]
	payload := parts[0] + "|" + parts[1]
	sig := parts[2]

	if !verifyPayload(secret, payload, sig) {
		return nil, fmt.Errorf("invalid cookie signature")
	}

	var expUnix int64
	if _, err := fmt.Sscanf(parts[1], "%d", &expUnix); err != nil {
		return nil, fmt.Errorf("invalid expiration")
	}

	expires := time.Unix(expUnix, 0)
	if time.Now().After(expires) {
		return nil, fmt.Errorf("session expired")
	}

	return &sessionData{
		Username:  username,
		ExpiresAt: expires,
	}, nil
}

// clearSessionCookie returns a cookie that clears the session
func clearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

func signPayload(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyPayload(secret []byte, payload, signature string) bool {
	expected := signPayload(secret, payload)
	return hmac.Equal([]byte(expected), []byte(signature))
}
