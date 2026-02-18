package web

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionCookieRoundTrip(t *testing.T) {
	secret, err := generateSessionSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}

	cookie := createSessionCookie(secret, "testuser")

	req := httptest.NewRequest("GET", "/admin/", nil)
	req.AddCookie(cookie)

	session, err := parseSessionCookie(secret, req)
	if err != nil {
		t.Fatalf("parse session: %v", err)
	}

	if session.Username != "testuser" {
		t.Errorf("username = %q, want %q", session.Username, "testuser")
	}

	if time.Until(session.ExpiresAt) < 7*time.Hour {
		t.Errorf("expiration too soon: %v", session.ExpiresAt)
	}
}

func TestSessionCookieInvalidSignature(t *testing.T) {
	secret1, _ := generateSessionSecret()
	secret2, _ := generateSessionSecret()

	cookie := createSessionCookie(secret1, "testuser")

	req := httptest.NewRequest("GET", "/admin/", nil)
	req.AddCookie(cookie)

	_, err := parseSessionCookie(secret2, req)
	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestSessionCookieNoCookie(t *testing.T) {
	secret, _ := generateSessionSecret()

	req := httptest.NewRequest("GET", "/admin/", nil)
	_, err := parseSessionCookie(secret, req)
	if err == nil {
		t.Error("expected error for missing cookie")
	}
}

func TestClearSessionCookie(t *testing.T) {
	cookie := clearSessionCookie()
	if cookie.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", cookie.MaxAge)
	}
	if cookie.Value != "" {
		t.Errorf("Value = %q, want empty", cookie.Value)
	}
}
