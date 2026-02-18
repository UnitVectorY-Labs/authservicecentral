package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireAuthRedirectsWhenNotAuthenticated(t *testing.T) {
	srv := newTestServer(t, false)
	srv.cfg.ControlPlaneEnabled = true

	handler := srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if loc := w.Header().Get("Location"); loc != "/admin/login" {
		t.Errorf("Location = %q, want /admin/login", loc)
	}
}

func TestRequireAuthPassesThroughWhenAuthenticated(t *testing.T) {
	srv := newTestServer(t, false)
	srv.cfg.ControlPlaneEnabled = true

	handler := srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		username := getUsername(r)
		if username != "testuser" {
			t.Errorf("username = %q, want %q", username, "testuser")
		}
		w.WriteHeader(http.StatusOK)
	})

	cookie := createSessionCookie(srv.sessionSecret, "testuser")

	req := httptest.NewRequest("GET", "/admin/", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestLoginPageRendersWhenNotAuthenticated(t *testing.T) {
	srv := newTestServer(t, false)
	srv.cfg.ControlPlaneEnabled = true
	// Re-register routes since control plane is now enabled
	srv.mux = http.NewServeMux()
	srv.routes()

	req := httptest.NewRequest("GET", "/admin/login", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()
	if !containsSubstring(body, "Sign in") {
		t.Error("expected login page to contain 'Sign in'")
	}
}

func TestLoginPageRedirectsWhenAuthenticated(t *testing.T) {
	srv := newTestServer(t, false)
	srv.cfg.ControlPlaneEnabled = true
	srv.mux = http.NewServeMux()
	srv.routes()

	cookie := createSessionCookie(srv.sessionSecret, "admin")
	req := httptest.NewRequest("GET", "/admin/login", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if loc := w.Header().Get("Location"); loc != "/admin/" {
		t.Errorf("Location = %q, want /admin/", loc)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	srv := newTestServer(t, false)
	srv.cfg.ControlPlaneEnabled = true
	srv.mux = http.NewServeMux()
	srv.routes()

	cookie := createSessionCookie(srv.sessionSecret, "admin")
	req := httptest.NewRequest("GET", "/admin/logout", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName && c.MaxAge == -1 {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie to be cleared")
	}
}

func TestAdminHomeRequiresAuth(t *testing.T) {
	srv := newTestServer(t, false)
	srv.cfg.ControlPlaneEnabled = true
	srv.mux = http.NewServeMux()
	srv.routes()

	req := httptest.NewRequest("GET", "/admin/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
}

func TestAdminHomeRendersWhenAuthenticated(t *testing.T) {
	srv := newTestServer(t, false)
	srv.cfg.ControlPlaneEnabled = true
	srv.mux = http.NewServeMux()
	srv.routes()

	cookie := createSessionCookie(srv.sessionSecret, "admin")
	req := httptest.NewRequest("GET", "/admin/", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()
	if !containsSubstring(body, "Admin Dashboard") {
		t.Error("expected home page to contain 'Admin Dashboard'")
	}
}

func TestControlPlaneDisabled(t *testing.T) {
	srv := newTestServer(t, false)
	// ControlPlaneEnabled is false by default in newTestServer

	for _, path := range []string{"/admin/login", "/admin/", "/admin/apps"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Errorf("path %s should not be available when control plane is disabled", path)
		}
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstringHelper(s, substr))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
