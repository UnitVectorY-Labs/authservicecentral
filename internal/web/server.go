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
	cfg      *config.Config
	db       *sql.DB
	keyStore *jwt.KeyStore
	mux      *http.ServeMux
}

// NewServer creates a new web server
func NewServer(cfg *config.Config, db *sql.DB, keyStore *jwt.KeyStore) *Server {
	s := &Server{
		cfg:      cfg,
		db:       db,
		keyStore: keyStore,
		mux:      http.NewServeMux(),
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
