package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

type Options struct {
	MaxBodyBytes       int64
	MaxBatchSize       int
	InsecureManagement bool
	ManagementAudience string
	Metrics            bool
	RateLimitPerSecond float64
	RateLimitBurst     int
}

type Server struct {
	backend       Backend
	authenticator Authenticator
	options       Options
	handler       http.Handler
	requests      atomic.Uint64
	errors        atomic.Uint64
	checks        atomic.Uint64
	allowed       atomic.Uint64
	denied        atomic.Uint64
	rateLimited   atomic.Uint64
	limiter       *tokenBucket
}

type requestIDKey struct{}

func RequestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey{}).(string)
	return value
}

func New(backend Backend, authenticator Authenticator, options Options) (*Server, error) {
	if backend == nil {
		return nil, errors.New("API backend is required")
	}
	if authenticator == nil {
		return nil, errors.New("API authenticator is required")
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = 1 << 20
	}
	if options.MaxBatchSize <= 0 {
		options.MaxBatchSize = 100
	}
	if options.ManagementAudience == "" {
		options.ManagementAudience = "serviceauth-management"
	}
	if options.RateLimitPerSecond < 0 || options.RateLimitBurst < 0 {
		return nil, errors.New("API rate limit and burst cannot be negative")
	}
	s := &Server{backend: backend, authenticator: authenticator, options: options}
	if options.RateLimitPerSecond > 0 && options.RateLimitBurst > 0 {
		s.limiter = newTokenBucket(options.RateLimitPerSecond, float64(options.RateLimitBurst))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.metadata)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("POST /oauth2/token", s.exchange)
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.ready)
	if options.Metrics {
		mux.HandleFunc("GET /metrics", s.metrics)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.writeError(w, r, Error(http.StatusNotFound, "not_found", "endpoint not found"))
	})

	mux.Handle("POST /v1/check", s.authenticated(http.HandlerFunc(s.check)))
	mux.Handle("POST /v1/audiences", s.management("management.audiences.write", http.HandlerFunc(s.createAudience)))
	mux.Handle("GET /v1/audiences", s.management("management.audiences.read", http.HandlerFunc(s.listAudiences)))
	mux.Handle("GET /v1/audiences/{id}", s.management("management.audiences.read", http.HandlerFunc(s.getAudience)))
	mux.Handle("PATCH /v1/audiences/{id}", s.management("management.audiences.write", http.HandlerFunc(s.patchAudience)))
	mux.Handle("DELETE /v1/audiences/{id}", s.management("management.audiences.write", http.HandlerFunc(s.deleteAudience)))
	mux.Handle("POST /v1/resources", s.management("management.resources.write", http.HandlerFunc(s.createResource)))
	mux.Handle("GET /v1/resources/{type}/{id}", s.management("management.resources.read", http.HandlerFunc(s.getResource)))
	mux.Handle("PATCH /v1/resources/{type}/{id}", s.management("management.resources.write", http.HandlerFunc(s.patchResource)))
	mux.Handle("DELETE /v1/resources/{type}/{id}", s.management("management.resources.write", http.HandlerFunc(s.deleteResource)))
	mux.Handle("PUT /v1/resources/{type}/{id}/relationships/{relation}", s.management("management.resources.write", http.HandlerFunc(s.putRelationship)))
	mux.Handle("DELETE /v1/resources/{type}/{id}/relationships/{relation}", s.management("management.resources.write", http.HandlerFunc(s.deleteRelationship)))
	mux.Handle("POST /v1/groups", s.management("management.groups.write", http.HandlerFunc(s.createGroup)))
	mux.Handle("GET /v1/groups/{id}", s.management("management.groups.read", http.HandlerFunc(s.getGroup)))
	mux.Handle("DELETE /v1/groups/{id}", s.management("management.groups.write", http.HandlerFunc(s.deleteGroup)))
	mux.Handle("POST /v1/groups/{id}/members", s.management("management.groups.write", http.HandlerFunc(s.addMember)))
	mux.Handle("DELETE /v1/groups/{id}/members", s.management("management.groups.write", http.HandlerFunc(s.deleteMember)))
	mux.Handle("POST /v1/grants", s.management("management.grants.write", http.HandlerFunc(s.createGrant)))
	mux.Handle("GET /v1/grants", s.management("management.grants.read", http.HandlerFunc(s.listGrants)))
	mux.Handle("DELETE /v1/grants/{id}", s.management("management.grants.write", http.HandlerFunc(s.deleteGrant)))
	s.handler = s.requestID(s.recover(s.count(s.rateLimit(mux))))
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) count(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.requests.Add(1); next.ServeHTTP(w, r) })
}
func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := safeRequestID(r.Header.Get("X-Request-ID"))
		if id == "" {
			id = randomRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}
func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				s.writeError(w, r, Error(http.StatusInternalServerError, "internal_error", "internal server error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := s.authenticate(r)
		if err != nil {
			s.auditAuthenticationFailure(r, "invalid_platform_token")
			s.writeError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, identity)))
	})
}
func (s *Server) management(permission string, next http.Handler) http.Handler {
	if s.options.InsecureManagement {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, Identity{Subject: "development-insecure-management"})))
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := s.authenticate(r)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		if identity.Audience != s.options.ManagementAudience {
			s.auditAuthenticationFailure(r, "wrong_management_audience")
			s.writeError(w, r, Error(http.StatusForbidden, "wrong_audience", "a management-audience token is required"))
			return
		}
		if !hasPermission(identity.Permissions, permission) {
			s.auditAuthenticationFailure(r, "missing_management_permission")
			s.writeError(w, r, Error(http.StatusForbidden, "insufficient_permission", "management permission is required"))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, identity)))
	})
}

func (s *Server) auditAuthenticationFailure(r *http.Request, category string) {
	if auditor, ok := s.backend.(AuthenticationFailureAuditor); ok {
		auditor.AuditAuthenticationFailure(r.Context(), RequestIDFromContext(r.Context()), category)
	}
}

type identityKey struct{}

func identityFrom(r *http.Request) Identity {
	identity, _ := r.Context().Value(identityKey{}).(Identity)
	return identity
}
func (s *Server) authenticate(r *http.Request) (Identity, error) {
	header := r.Header.Get("Authorization")
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return Identity{}, Error(http.StatusUnauthorized, "invalid_token", "a bearer token is required")
	}
	identity, err := s.authenticator.Authenticate(r.Context(), parts[1])
	if err != nil {
		return Identity{}, Error(http.StatusUnauthorized, "invalid_token", "the bearer token is invalid")
	}
	if identity.Subject == "" {
		return Identity{}, Error(http.StatusUnauthorized, "invalid_token", "the bearer token has no subject")
	}
	return identity, nil
}

func (s *Server) metadata(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.OAuthMetadata(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.JWKS(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.options.MaxBodyBytes)
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		s.writeError(w, r, Error(http.StatusBadRequest, "invalid_request", "content type must be application/x-www-form-urlencoded"))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, Error(http.StatusBadRequest, "invalid_request", "invalid token exchange form"))
		return
	}
	request := TokenExchangeRequest{GrantType: r.PostForm.Get("grant_type"), SubjectToken: r.PostForm.Get("subject_token"), SubjectTokenType: r.PostForm.Get("subject_token_type"), ActorToken: r.PostForm.Get("actor_token"), ActorTokenType: r.PostForm.Get("actor_token_type"), Audience: r.PostForm.Get("audience")}
	response, err := s.backend.Exchange(r.Context(), request)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, response)
}
func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, statusEnvelope{Status: "ok"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.backend.Ready(r.Context()); err != nil {
		s.writeError(w, r, Error(http.StatusServiceUnavailable, "not_ready", "service is not ready"))
		return
	}
	writeJSON(w, http.StatusOK, statusEnvelope{Status: "ready"})
}

func (s *Server) createAudience(w http.ResponseWriter, r *http.Request) {
	var req Audience
	if !s.decode(w, r, &req, false) {
		return
	}
	value, err := s.backend.CreateAudience(r.Context(), identityFrom(r), req)
	s.result(w, r, http.StatusCreated, value, err)
}
func (s *Server) listAudiences(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.ListAudiences(r.Context(), identityFrom(r))
	s.result(w, r, http.StatusOK, map[string]any{"audiences": value}, err)
}
func (s *Server) getAudience(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.GetAudience(r.Context(), identityFrom(r), r.PathValue("id"))
	s.result(w, r, http.StatusOK, value, err)
}
func (s *Server) patchAudience(w http.ResponseWriter, r *http.Request) {
	var req AudiencePatch
	if !s.decode(w, r, &req, false) {
		return
	}
	value, err := s.backend.PatchAudience(r.Context(), identityFrom(r), r.PathValue("id"), req)
	s.result(w, r, http.StatusOK, value, err)
}
func (s *Server) deleteAudience(w http.ResponseWriter, r *http.Request) {
	s.noContent(w, r, s.backend.DeleteAudience(r.Context(), identityFrom(r), r.PathValue("id")))
}
func (s *Server) createResource(w http.ResponseWriter, r *http.Request) {
	var req Resource
	if !s.decode(w, r, &req, false) {
		return
	}
	value, err := s.backend.CreateResource(r.Context(), identityFrom(r), req)
	s.result(w, r, http.StatusCreated, value, err)
}
func resourceRef(r *http.Request) ResourceRef {
	return ResourceRef{Type: r.PathValue("type"), ID: r.PathValue("id")}
}
func (s *Server) getResource(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.GetResource(r.Context(), identityFrom(r), resourceRef(r))
	s.result(w, r, http.StatusOK, value, err)
}
func (s *Server) patchResource(w http.ResponseWriter, r *http.Request) {
	var req ResourcePatch
	if !s.decode(w, r, &req, false) {
		return
	}
	value, err := s.backend.PatchResource(r.Context(), identityFrom(r), resourceRef(r), req)
	s.result(w, r, http.StatusOK, value, err)
}
func (s *Server) deleteResource(w http.ResponseWriter, r *http.Request) {
	s.noContent(w, r, s.backend.DeleteResource(r.Context(), identityFrom(r), resourceRef(r)))
}
func (s *Server) putRelationship(w http.ResponseWriter, r *http.Request) {
	var req RelationshipMutation
	if !s.decode(w, r, &req, false) {
		return
	}
	s.noContent(w, r, s.backend.PutRelationship(r.Context(), identityFrom(r), resourceRef(r), r.PathValue("relation"), req))
}
func (s *Server) deleteRelationship(w http.ResponseWriter, r *http.Request) {
	var req RelationshipMutation
	if !s.decode(w, r, &req, true) {
		return
	}
	s.noContent(w, r, s.backend.DeleteRelationship(r.Context(), identityFrom(r), resourceRef(r), r.PathValue("relation"), req))
}
func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var req Group
	if !s.decode(w, r, &req, false) {
		return
	}
	value, err := s.backend.CreateGroup(r.Context(), identityFrom(r), req)
	s.result(w, r, http.StatusCreated, value, err)
}
func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.GetGroup(r.Context(), identityFrom(r), r.PathValue("id"))
	s.result(w, r, http.StatusOK, value, err)
}
func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	s.noContent(w, r, s.backend.DeleteGroup(r.Context(), identityFrom(r), r.PathValue("id")))
}
func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	var req MembershipRequest
	if !s.decode(w, r, &req, false) {
		return
	}
	s.noContent(w, r, s.backend.AddMember(r.Context(), identityFrom(r), r.PathValue("id"), req))
}
func (s *Server) deleteMember(w http.ResponseWriter, r *http.Request) {
	var req MembershipRequest
	if !s.decode(w, r, &req, false) {
		return
	}
	s.noContent(w, r, s.backend.DeleteMember(r.Context(), identityFrom(r), r.PathValue("id"), req))
}
func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	var req Grant
	if !s.decode(w, r, &req, false) {
		return
	}
	value, err := s.backend.CreateGrant(r.Context(), identityFrom(r), req)
	s.result(w, r, http.StatusCreated, value, err)
}
func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.ListGrants(r.Context(), identityFrom(r))
	s.result(w, r, http.StatusOK, map[string]any{"grants": value}, err)
}
func (s *Server) deleteGrant(w http.ResponseWriter, r *http.Request) {
	s.noContent(w, r, s.backend.DeleteGrant(r.Context(), identityFrom(r), r.PathValue("id")))
}
func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	var req CheckRequest
	if !s.decode(w, r, &req, false) {
		return
	}
	if len(req.Checks) == 0 || len(req.Checks) > s.options.MaxBatchSize {
		s.writeError(w, r, Error(http.StatusBadRequest, "invalid_batch", "checks must contain between 1 and "+strconv.Itoa(s.options.MaxBatchSize)+" items"))
		return
	}
	for _, check := range req.Checks {
		if check.Permission == "" || check.Resource.Type == "" || check.Resource.ID == "" {
			s.writeError(w, r, Error(http.StatusBadRequest, "invalid_check", "each check requires permission and resource type/id"))
			return
		}
	}
	s.checks.Add(uint64(len(req.Checks)))
	value, err := s.backend.Check(r.Context(), identityFrom(r), req)
	if err == nil {
		for _, result := range value.Results {
			if result.Allowed {
				s.allowed.Add(1)
			} else {
				s.denied.Add(1)
			}
		}
	}
	s.result(w, r, http.StatusOK, value, err)
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, dst any, optional bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, s.options.MaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(dst)
	if optional && errors.Is(err, io.EOF) {
		return true
	}
	if err != nil {
		s.writeError(w, r, Error(http.StatusBadRequest, "invalid_json", "request body must be valid JSON"))
		return false
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.writeError(w, r, Error(http.StatusBadRequest, "invalid_json", "request body must contain one JSON value"))
		return false
	}
	return true
}
func (s *Server) result(w http.ResponseWriter, r *http.Request, status int, value any, err error) {
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, status, value)
}
func (s *Server) noContent(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	s.errors.Add(1)
	status, code, message := http.StatusInternalServerError, "internal_error", "internal server error"
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		status, code, message = apiErr.Status, apiErr.Code, apiErr.Message
	} else if errors.Is(err, ErrNotFound) {
		status, code, message = http.StatusNotFound, "not_found", "resource not found"
	} else if errors.Is(err, ErrUnavailable) {
		status, code, message = http.StatusServiceUnavailable, "service_unavailable", "storage or authorization service is unavailable"
	}
	if status < 400 || status > 599 {
		status, code, message = http.StatusInternalServerError, "internal_error", "internal server error"
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	var envelope errorEnvelope
	envelope.Error.Code, envelope.Error.Message, envelope.Error.RequestID = code, message, RequestIDFromContext(r.Context())
	writeJSON(w, status, envelope)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func hasPermission(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func safeRequestID(value string) string {
	if len(value) == 0 || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.", r)) {
			return ""
		}
	}
	return value
}
func randomRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "request"
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "serviceauth_http_requests_total %d\nserviceauth_http_errors_total %d\nserviceauth_http_rate_limited_total %d\nserviceauth_authorization_checks_total %d\nserviceauth_authorization_allowed_total %d\nserviceauth_authorization_denied_total %d\n", s.requests.Load(), s.errors.Load(), s.rateLimited.Load(), s.checks.Load(), s.allowed.Load(), s.denied.Load())
}
