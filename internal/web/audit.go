package web

import (
	"log"
	"net"
	"net/http"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

func (s *Server) recordControlPlaneAudit(
	r *http.Request,
	action, targetType string,
	targetPK, before, after, metadata interface{},
) {
	if s.db == nil {
		return
	}
	if err := database.CreateControlPlaneAuditLog(
		r.Context(),
		s.db,
		"user",
		truncateAuditString(getUsername(r), 255),
		truncateAuditString(requestIP(r), 255),
		truncateAuditString(r.UserAgent(), 255),
		action,
		targetType,
		targetPK,
		before,
		after,
		metadata,
	); err != nil {
		log.Printf("error creating control-plane audit log: %v", err)
	}
}

func (s *Server) recordDataPlaneAudit(
	r *http.Request,
	subjectApplicationID, audienceApplicationID *int64,
	scopes []string,
	decision, reason string,
	details interface{},
) {
	if s.db == nil {
		return
	}
	if err := database.CreateDataPlaneAuditLog(
		r.Context(),
		s.db,
		subjectApplicationID,
		audienceApplicationID,
		scopes,
		decision,
		truncateAuditString(reason, 255),
		truncateAuditString(r.Header.Get("X-Request-Id"), 255),
		details,
	); err != nil {
		log.Printf("error creating data-plane audit log: %v", err)
	}
}

func requestIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func truncateAuditString(v string, max int) string {
	if max > 0 && len(v) > max {
		return v[:max]
	}
	return v
}

func int64Ptr(v int64) *int64 {
	return &v
}
