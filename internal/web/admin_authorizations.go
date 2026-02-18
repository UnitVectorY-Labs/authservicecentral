package web

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

// --- Authorization New ---

type authorizationNewData struct {
	pageData
	SubjectApp *database.ApplicationDetail
	Apps       []database.ApplicationListItem
}

func (s *Server) handleAuthorizationNew(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	ctx := r.Context()

	app, err := database.GetApplicationDetail(ctx, s.db, subject)
	if err != nil {
		log.Printf("error getting application: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if app == nil {
		http.NotFound(w, r)
		return
	}

	apps, err := database.ListApplications(ctx, s.db, "", 1000, 0)
	if err != nil {
		log.Printf("error listing applications: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := authorizationNewData{
		pageData:   newPageData(r, "apps"),
		SubjectApp: app,
		Apps:       apps,
	}
	renderPage(w, r, authNewTmpl, data)
}

// --- Authorization Create ---

func (s *Server) handleAuthorizationCreate(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	subjectApp, err := database.GetApplicationDetail(ctx, s.db, subject)
	if err != nil {
		log.Printf("error getting subject application: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if subjectApp == nil {
		http.NotFound(w, r)
		return
	}

	audienceSubject := r.FormValue("audience")
	description := strings.TrimSpace(r.FormValue("description"))

	if audienceSubject == "" {
		apps, _ := database.ListApplications(ctx, s.db, "", 1000, 0)
		data := authorizationNewData{
			pageData:   newPageData(r, "apps"),
			SubjectApp: subjectApp,
			Apps:       apps,
		}
		data.Error = "Audience application is required."
		w.WriteHeader(http.StatusUnprocessableEntity)
		renderPage(w, r, authNewTmpl, data)
		return
	}

	audienceApp, err := database.GetApplicationDetail(ctx, s.db, audienceSubject)
	if err != nil {
		log.Printf("error getting audience application: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if audienceApp == nil {
		apps, _ := database.ListApplications(ctx, s.db, "", 1000, 0)
		data := authorizationNewData{
			pageData:   newPageData(r, "apps"),
			SubjectApp: subjectApp,
			Apps:       apps,
		}
		data.Error = "Audience application not found."
		w.WriteHeader(http.StatusUnprocessableEntity)
		renderPage(w, r, authNewTmpl, data)
		return
	}

	if err := database.CreateAuthorization(ctx, s.db, subjectApp.ID, audienceApp.ID, description); err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			apps, _ := database.ListApplications(ctx, s.db, "", 1000, 0)
			data := authorizationNewData{
				pageData:   newPageData(r, "apps"),
				SubjectApp: subjectApp,
				Apps:       apps,
			}
			data.Error = "This authorization already exists."
			w.WriteHeader(http.StatusUnprocessableEntity)
			renderPage(w, r, authNewTmpl, data)
			return
		}
		log.Printf("error creating authorization: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/authorizations/%s", subject, audienceSubject), http.StatusSeeOther)
}

// --- Authorization Detail ---

type authorizationDetailData struct {
	pageData
	SubjectApp      *database.ApplicationDetail
	AudienceApp     *database.ApplicationDetail
	Authorization   *database.Authorization
	GrantedScopes   []string
	AvailableScopes []database.ApplicationScope
}

func (s *Server) handleAuthorizationDetail(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	audience := r.PathValue("audience")
	ctx := r.Context()

	subjectApp, err := database.GetApplicationDetail(ctx, s.db, subject)
	if err != nil {
		log.Printf("error getting subject application: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if subjectApp == nil {
		http.NotFound(w, r)
		return
	}

	audienceApp, err := database.GetApplicationDetail(ctx, s.db, audience)
	if err != nil {
		log.Printf("error getting audience application: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if audienceApp == nil {
		http.NotFound(w, r)
		return
	}

	auth, err := database.LookupAuthorization(ctx, s.db, subjectApp.ID, audienceApp.ID)
	if err != nil {
		log.Printf("error looking up authorization: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if auth == nil {
		http.NotFound(w, r)
		return
	}

	grantedScopes, err := database.LookupAuthorizedScopes(ctx, s.db, subjectApp.ID, audienceApp.ID)
	if err != nil {
		log.Printf("error looking up granted scopes: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	availableScopes, err := database.ListApplicationScopes(ctx, s.db, audienceApp.ID)
	if err != nil {
		log.Printf("error listing audience scopes: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := authorizationDetailData{
		pageData:        newPageData(r, "apps"),
		SubjectApp:      subjectApp,
		AudienceApp:     audienceApp,
		Authorization:   auth,
		GrantedScopes:   grantedScopes,
		AvailableScopes: availableScopes,
	}
	renderPage(w, r, authDetailTmpl, data)
}

// --- Authorization Update ---

func (s *Server) handleAuthorizationUpdate(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	audience := r.PathValue("audience")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	subjectApp, err := database.GetApplicationDetail(ctx, s.db, subject)
	if err != nil || subjectApp == nil {
		http.NotFound(w, r)
		return
	}

	audienceApp, err := database.GetApplicationDetail(ctx, s.db, audience)
	if err != nil || audienceApp == nil {
		http.NotFound(w, r)
		return
	}

	enabled := r.FormValue("enabled") == "true"
	if err := database.UpdateAuthorization(ctx, s.db, subjectApp.ID, audienceApp.ID, enabled); err != nil {
		log.Printf("error updating authorization: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/authorizations/%s", subject, audience), http.StatusSeeOther)
}

// --- Authorization Delete ---

func (s *Server) handleAuthorizationDelete(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	audience := r.PathValue("audience")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	subjectApp, err := database.GetApplicationDetail(ctx, s.db, subject)
	if err != nil || subjectApp == nil {
		http.NotFound(w, r)
		return
	}

	audienceApp, err := database.GetApplicationDetail(ctx, s.db, audience)
	if err != nil || audienceApp == nil {
		http.NotFound(w, r)
		return
	}

	if err := database.DeleteAuthorization(ctx, s.db, subjectApp.ID, audienceApp.ID); err != nil {
		log.Printf("error deleting authorization: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s?tab=authorizations", subject), http.StatusSeeOther)
}

// --- Authorization Scope Add ---

func (s *Server) handleAuthorizationScopeAdd(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	audience := r.PathValue("audience")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	subjectApp, err := database.GetApplicationDetail(ctx, s.db, subject)
	if err != nil || subjectApp == nil {
		http.NotFound(w, r)
		return
	}

	audienceApp, err := database.GetApplicationDetail(ctx, s.db, audience)
	if err != nil || audienceApp == nil {
		http.NotFound(w, r)
		return
	}

	scope := r.FormValue("scope")
	if scope == "" {
		http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/authorizations/%s", subject, audience), http.StatusSeeOther)
		return
	}

	if err := database.CreateAuthorizationScope(ctx, s.db, subjectApp.ID, audienceApp.ID, scope); err != nil {
		log.Printf("error adding authorization scope: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/authorizations/%s", subject, audience), http.StatusSeeOther)
}

// --- Authorization Scope Remove ---

func (s *Server) handleAuthorizationScopeRemove(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	audience := r.PathValue("audience")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	subjectApp, err := database.GetApplicationDetail(ctx, s.db, subject)
	if err != nil || subjectApp == nil {
		http.NotFound(w, r)
		return
	}

	audienceApp, err := database.GetApplicationDetail(ctx, s.db, audience)
	if err != nil || audienceApp == nil {
		http.NotFound(w, r)
		return
	}

	scope := r.FormValue("scope")
	if scope == "" {
		http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/authorizations/%s", subject, audience), http.StatusSeeOther)
		return
	}

	if err := database.DeleteAuthorizationScope(ctx, s.db, subjectApp.ID, audienceApp.ID, scope); err != nil {
		log.Printf("error removing authorization scope: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/authorizations/%s", subject, audience), http.StatusSeeOther)
}
