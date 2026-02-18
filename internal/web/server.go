package web

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/jwt"
)

// Server holds the HTTP server dependencies
type Server struct {
	cfg           *config.Config
	db            *sql.DB
	keyStore      *jwt.KeyStore
	mux           *http.ServeMux
	sessionSecret []byte
}

// NewServer creates a new web server
func NewServer(cfg *config.Config, db *sql.DB, keyStore *jwt.KeyStore) *Server {
	secret, err := generateSessionSecret()
	if err != nil {
		log.Fatalf("failed to generate session secret: %v", err)
	}

	s := &Server{
		cfg:           cfg,
		db:            db,
		keyStore:      keyStore,
		mux:           http.NewServeMux(),
		sessionSecret: secret,
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	// Static files
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(StaticFS())))

	// Data plane endpoints
	if s.cfg.DataPlaneEnabled {
		s.mux.HandleFunc("GET /.well-known/openid-configuration", s.handleOpenIDConfiguration)
		s.mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
		s.mux.HandleFunc("POST /v1/token", s.handleToken)
	}

	// Control plane endpoints
	if s.cfg.ControlPlaneEnabled {
		s.mux.HandleFunc("GET /admin/login", s.handleLoginPage)
		s.mux.HandleFunc("POST /admin/login", s.handleLoginSubmit)
		s.mux.HandleFunc("GET /admin/logout", s.handleLogout)
		s.mux.HandleFunc("GET /admin/{$}", s.requireAuth(s.handleAdminHome))
		s.mux.HandleFunc("GET /admin/apps", s.requireAuth(s.handleAppsList))

		// Application CRUD
		s.mux.HandleFunc("GET /admin/apps/new", s.requireAuth(s.handleAppsNew))
		s.mux.HandleFunc("POST /admin/apps/new", s.requireAuth(s.handleAppsCreate))
		s.mux.HandleFunc("GET /admin/apps/{subject}", s.requireAuth(s.handleAppDetail))
		s.mux.HandleFunc("POST /admin/apps/{subject}", s.requireAuth(s.handleAppUpdate))
		s.mux.HandleFunc("POST /admin/apps/{subject}/scopes", s.requireAuth(s.handleScopeCreate))
		s.mux.HandleFunc("POST /admin/apps/{subject}/scopes/delete", s.requireAuth(s.handleScopeDelete))
		s.mux.HandleFunc("POST /admin/apps/{subject}/credentials", s.requireAuth(s.handleCredentialCreate))
		s.mux.HandleFunc("POST /admin/apps/{subject}/credentials/disable", s.requireAuth(s.handleCredentialDisable))

		// Outbound authorizations
		s.mux.HandleFunc("GET /admin/apps/{subject}/authorizations/new", s.requireAuth(s.handleAuthorizationNew))
		s.mux.HandleFunc("POST /admin/apps/{subject}/authorizations/new", s.requireAuth(s.handleAuthorizationCreate))
		s.mux.HandleFunc("GET /admin/apps/{subject}/authorizations/{audience}", s.requireAuth(s.handleAuthorizationDetail))
		s.mux.HandleFunc("POST /admin/apps/{subject}/authorizations/{audience}", s.requireAuth(s.handleAuthorizationUpdate))
		s.mux.HandleFunc("POST /admin/apps/{subject}/authorizations/{audience}/delete", s.requireAuth(s.handleAuthorizationDelete))
		s.mux.HandleFunc("POST /admin/apps/{subject}/authorizations/{audience}/scopes", s.requireAuth(s.handleAuthorizationScopeAdd))
		s.mux.HandleFunc("POST /admin/apps/{subject}/authorizations/{audience}/scopes/delete", s.requireAuth(s.handleAuthorizationScopeRemove))

		// Identity Providers
		s.mux.HandleFunc("GET /admin/providers", s.requireAuth(s.handleProvidersList))
		s.mux.HandleFunc("GET /admin/providers/new", s.requireAuth(s.handleProviderNew))
		s.mux.HandleFunc("POST /admin/providers/new", s.requireAuth(s.handleProviderCreate))
		s.mux.HandleFunc("GET /admin/providers/{id}", s.requireAuth(s.handleProviderDetail))
		s.mux.HandleFunc("POST /admin/providers/{id}", s.requireAuth(s.handleProviderUpdate))
		s.mux.HandleFunc("POST /admin/providers/{id}/delete", s.requireAuth(s.handleProviderDelete))

		// Workloads (nested under providers)
		s.mux.HandleFunc("GET /admin/providers/{id}/workloads/new", s.requireAuth(s.handleWorkloadNew))
		s.mux.HandleFunc("POST /admin/providers/{id}/workloads/new", s.requireAuth(s.handleWorkloadCreate))
		s.mux.HandleFunc("GET /admin/providers/{id}/workloads/{workloadID}", s.requireAuth(s.handleWorkloadDetail))
		s.mux.HandleFunc("POST /admin/providers/{id}/workloads/{workloadID}", s.requireAuth(s.handleWorkloadUpdate))
		s.mux.HandleFunc("POST /admin/providers/{id}/workloads/{workloadID}/delete", s.requireAuth(s.handleWorkloadDelete))
		s.mux.HandleFunc("POST /admin/providers/{id}/workloads/{workloadID}/link", s.requireAuth(s.handleWorkloadLink))
		s.mux.HandleFunc("POST /admin/providers/{id}/workloads/{workloadID}/unlink", s.requireAuth(s.handleWorkloadUnlink))
	}

	// Health check
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
}

// ServeHTTP implements the http.Handler interface
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// ListenAndServe starts the HTTP server
func (s *Server) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.HTTPAddr, s.cfg.HTTPPort)
	log.Printf("listening on %s", addr)
	return http.ListenAndServe(addr, s)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	issuer := s.cfg.JWTIssuer
	response := map[string]interface{}{
		"issuer":                issuer,
		"jwks_uri":             issuer + "/.well-known/jwks.json",
		"token_endpoint":       issuer + "/v1/token",
		"grant_types_supported": []string{
			"client_credentials",
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := s.keyStore.JWKS()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(jwks)
}

func writeJSON(w http.ResponseWriter, statusCode int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(v)
}
