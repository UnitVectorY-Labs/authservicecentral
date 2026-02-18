package web

import (
	"net/http/httptest"
	"testing"
)

func TestRequestIPParsesHostPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	if got := requestIP(req); got != "192.0.2.10" {
		t.Fatalf("requestIP() = %q, want %q", got, "192.0.2.10")
	}
}

func TestTruncateAuditString(t *testing.T) {
	if got := truncateAuditString("abcdef", 4); got != "abcd" {
		t.Fatalf("truncateAuditString() = %q, want %q", got, "abcd")
	}
	if got := truncateAuditString("abc", 4); got != "abc" {
		t.Fatalf("truncateAuditString() = %q, want %q", got, "abc")
	}
}

func TestRecordAuditNoDB(t *testing.T) {
	srv := newTestServer(t, false)
	req := httptest.NewRequest("GET", "/", nil)
	srv.recordControlPlaneAudit(req, "update", "application", map[string]interface{}{"id": 1}, nil, nil, nil)
	srv.recordDataPlaneAudit(req, nil, nil, nil, "deny", "invalid request", nil)
}
