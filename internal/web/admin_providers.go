package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

const providersPerPage = 20

// --- Provider Data Types ---

type providersListData struct {
	pageData
	Providers  []database.IdentityProviderListItem
	Page       int
	TotalPages int
	Total      int
	StartItem  int
	EndItem    int
	PrevPage   int
	NextPage   int
}

type providerNewData struct {
	pageData
	Name      string
	IssuerURL string
	JWKSURL   string
}

type providerDetailData struct {
	pageData
	Provider  *database.IdentityProvider
	Workloads []database.WorkloadListItem
}

type workloadNewData struct {
	pageData
	Provider *database.IdentityProvider
	Name     string
	Selector string
}

type workloadDetailData struct {
	pageData
	Provider    *database.IdentityProvider
	Workload    *database.Workload
	SelectorStr string
	Apps        []database.WorkloadApplicationItem
	AllApps     []database.ApplicationListItem
}

// --- Provider Handlers ---

func (s *Server) handleProvidersList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}

	offset := (page - 1) * providersPerPage

	total, err := database.CountIdentityProviders(ctx, s.db)
	if err != nil {
		log.Printf("error counting identity providers: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	providers, err := database.ListIdentityProviders(ctx, s.db, providersPerPage, offset)
	if err != nil {
		log.Printf("error listing identity providers: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	totalPages := (total + providersPerPage - 1) / providersPerPage
	if totalPages < 1 {
		totalPages = 1
	}

	startItem := offset + 1
	endItem := offset + len(providers)
	if total == 0 {
		startItem = 0
	}

	data := providersListData{
		pageData:   newPageData(r, "providers"),
		Providers:  providers,
		Page:       page,
		TotalPages: totalPages,
		Total:      total,
		StartItem:  startItem,
		EndItem:    endItem,
		PrevPage:   page - 1,
		NextPage:   page + 1,
	}

	renderPage(w, r, providersListTmpl, data)
}

func (s *Server) handleProviderNew(w http.ResponseWriter, r *http.Request) {
	data := providerNewData{
		pageData: newPageData(r, "providers"),
	}
	renderPage(w, r, providerNewTmpl, data)
}

func (s *Server) handleProviderCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	issuerURL := strings.TrimSpace(r.FormValue("issuer_url"))
	jwksURL := strings.TrimSpace(r.FormValue("jwks_url"))

	renderError := func(msg string) {
		data := providerNewData{
			pageData:  newPageData(r, "providers"),
			Name:      name,
			IssuerURL: issuerURL,
			JWKSURL:   jwksURL,
		}
		data.Error = msg
		w.WriteHeader(http.StatusUnprocessableEntity)
		renderPage(w, r, providerNewTmpl, data)
	}

	if name == "" {
		renderError("Name is required.")
		return
	}
	if issuerURL == "" {
		renderError("Issuer URL is required.")
		return
	}

	ctx := r.Context()
	provider, err := database.CreateIdentityProvider(ctx, s.db, name, "oidc", issuerURL, jwksURL)
	if err != nil {
		log.Printf("error creating identity provider: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.recordControlPlaneAudit(
		r,
		"create",
		"identity_provider",
		map[string]interface{}{"id": provider.ID},
		nil,
		map[string]interface{}{"id": provider.ID, "name": provider.Name, "issuer_url": provider.IssuerURL, "jwks_url": provider.JWKSURL.String},
		nil,
	)

	http.Redirect(w, r, fmt.Sprintf("/admin/providers/%d", provider.ID), http.StatusSeeOther)
}

func (s *Server) handleProviderDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	provider, err := database.GetIdentityProvider(ctx, s.db, id)
	if err != nil {
		log.Printf("error getting identity provider: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if provider == nil {
		http.NotFound(w, r)
		return
	}

	workloads, err := database.ListWorkloads(ctx, s.db, provider.ID)
	if err != nil {
		log.Printf("error listing workloads: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := providerDetailData{
		pageData:  newPageData(r, "providers"),
		Provider:  provider,
		Workloads: workloads,
	}

	renderPage(w, r, providerDetailTmpl, data)
}

func (s *Server) handleProviderUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	provider, err := database.GetIdentityProvider(ctx, s.db, id)
	if err != nil || provider == nil {
		http.NotFound(w, r)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	issuerURL := strings.TrimSpace(r.FormValue("issuer_url"))
	jwksURL := strings.TrimSpace(r.FormValue("jwks_url"))

	if name == "" || issuerURL == "" {
		workloads, _ := database.ListWorkloads(ctx, s.db, provider.ID)
		data := providerDetailData{
			pageData:  newPageData(r, "providers"),
			Provider:  provider,
			Workloads: workloads,
		}
		data.Error = "Name and Issuer URL are required."
		w.WriteHeader(http.StatusUnprocessableEntity)
		renderPage(w, r, providerDetailTmpl, data)
		return
	}

	if err := database.UpdateIdentityProvider(ctx, s.db, id, name, issuerURL, jwksURL); err != nil {
		log.Printf("error updating identity provider: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.recordControlPlaneAudit(
		r,
		"update",
		"identity_provider",
		map[string]interface{}{"id": provider.ID},
		map[string]interface{}{"name": provider.Name, "issuer_url": provider.IssuerURL, "jwks_url": provider.JWKSURL.String},
		map[string]interface{}{"name": name, "issuer_url": issuerURL, "jwks_url": jwksURL},
		nil,
	)

	http.Redirect(w, r, fmt.Sprintf("/admin/providers/%d", id), http.StatusSeeOther)
}

func (s *Server) handleProviderDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	provider, err := database.GetIdentityProvider(ctx, s.db, id)
	if err != nil || provider == nil {
		http.NotFound(w, r)
		return
	}

	if err := database.DeleteIdentityProvider(ctx, s.db, id); err != nil {
		log.Printf("error deleting identity provider: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.recordControlPlaneAudit(
		r,
		"delete",
		"identity_provider",
		map[string]interface{}{"id": provider.ID},
		map[string]interface{}{"name": provider.Name, "issuer_url": provider.IssuerURL, "jwks_url": provider.JWKSURL.String},
		nil,
		nil,
	)

	http.Redirect(w, r, "/admin/providers", http.StatusSeeOther)
}

// --- Workload Handlers ---

func (s *Server) handleWorkloadNew(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	provider, err := database.GetIdentityProvider(ctx, s.db, id)
	if err != nil {
		log.Printf("error getting identity provider: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if provider == nil {
		http.NotFound(w, r)
		return
	}

	data := workloadNewData{
		pageData: newPageData(r, "providers"),
		Provider: provider,
	}
	renderPage(w, r, workloadNewTmpl, data)
}

func (s *Server) handleWorkloadCreate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	provider, err := database.GetIdentityProvider(ctx, s.db, id)
	if err != nil {
		log.Printf("error getting identity provider: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if provider == nil {
		http.NotFound(w, r)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	selectorStr := strings.TrimSpace(r.FormValue("selector"))

	renderError := func(msg string) {
		data := workloadNewData{
			pageData: newPageData(r, "providers"),
			Provider: provider,
			Name:     name,
			Selector: selectorStr,
		}
		data.Error = msg
		w.WriteHeader(http.StatusUnprocessableEntity)
		renderPage(w, r, workloadNewTmpl, data)
	}

	if name == "" {
		renderError("Name is required.")
		return
	}
	if selectorStr == "" {
		renderError("Selector is required.")
		return
	}

	if !json.Valid([]byte(selectorStr)) {
		renderError("Selector must be valid JSON.")
		return
	}

	workload, err := database.CreateWorkload(ctx, s.db, provider.ID, name, json.RawMessage(selectorStr))
	if err != nil {
		log.Printf("error creating workload: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.recordControlPlaneAudit(
		r,
		"create",
		"workload",
		map[string]interface{}{"id": workload.ID},
		nil,
		map[string]interface{}{"id": workload.ID, "identity_provider_id": workload.IdentityProviderID, "name": workload.Name, "selector": selectorStr},
		nil,
	)

	http.Redirect(w, r, fmt.Sprintf("/admin/providers/%d/workloads/%d", provider.ID, workload.ID), http.StatusSeeOther)
}

func (s *Server) handleWorkloadDetail(w http.ResponseWriter, r *http.Request) {
	providerID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	workloadID, err := strconv.ParseInt(r.PathValue("workloadID"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	provider, err := database.GetIdentityProvider(ctx, s.db, providerID)
	if err != nil {
		log.Printf("error getting identity provider: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if provider == nil {
		http.NotFound(w, r)
		return
	}

	workload, err := database.GetWorkload(ctx, s.db, workloadID)
	if err != nil {
		log.Printf("error getting workload: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if workload == nil || workload.IdentityProviderID != providerID {
		http.NotFound(w, r)
		return
	}

	// Pretty-print the selector JSON
	var selectorStr string
	if len(workload.Selector) > 0 {
		var buf json.RawMessage
		if err := json.Unmarshal(workload.Selector, &buf); err == nil {
			pretty, err := json.MarshalIndent(buf, "", "  ")
			if err == nil {
				selectorStr = string(pretty)
			} else {
				selectorStr = string(workload.Selector)
			}
		} else {
			selectorStr = string(workload.Selector)
		}
	}

	apps, err := database.ListWorkloadApplications(ctx, s.db, workloadID)
	if err != nil {
		log.Printf("error listing workload applications: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	allApps, err := database.ListApplications(ctx, s.db, "", 1000, 0)
	if err != nil {
		log.Printf("error listing applications: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := workloadDetailData{
		pageData:    newPageData(r, "providers"),
		Provider:    provider,
		Workload:    workload,
		SelectorStr: selectorStr,
		Apps:        apps,
		AllApps:     allApps,
	}

	renderPage(w, r, workloadDetailTmpl, data)
}

func (s *Server) handleWorkloadUpdate(w http.ResponseWriter, r *http.Request) {
	providerID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	workloadID, err := strconv.ParseInt(r.PathValue("workloadID"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	provider, err := database.GetIdentityProvider(ctx, s.db, providerID)
	if err != nil || provider == nil {
		http.NotFound(w, r)
		return
	}

	workload, err := database.GetWorkload(ctx, s.db, workloadID)
	if err != nil || workload == nil || workload.IdentityProviderID != providerID {
		http.NotFound(w, r)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	selectorStr := strings.TrimSpace(r.FormValue("selector"))

	renderError := func(msg string) {
		apps, _ := database.ListWorkloadApplications(ctx, s.db, workloadID)
		allApps, _ := database.ListApplications(ctx, s.db, "", 1000, 0)
		data := workloadDetailData{
			pageData:    newPageData(r, "providers"),
			Provider:    provider,
			Workload:    workload,
			SelectorStr: selectorStr,
			Apps:        apps,
			AllApps:     allApps,
		}
		data.Error = msg
		w.WriteHeader(http.StatusUnprocessableEntity)
		renderPage(w, r, workloadDetailTmpl, data)
	}

	if name == "" {
		renderError("Name is required.")
		return
	}
	if selectorStr == "" {
		renderError("Selector is required.")
		return
	}
	if !json.Valid([]byte(selectorStr)) {
		renderError("Selector must be valid JSON.")
		return
	}

	if err := database.UpdateWorkload(ctx, s.db, workloadID, name, json.RawMessage(selectorStr)); err != nil {
		log.Printf("error updating workload: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.recordControlPlaneAudit(
		r,
		"update",
		"workload",
		map[string]interface{}{"id": workload.ID},
		map[string]interface{}{"name": workload.Name, "selector": string(workload.Selector)},
		map[string]interface{}{"name": name, "selector": selectorStr},
		nil,
	)

	http.Redirect(w, r, fmt.Sprintf("/admin/providers/%d/workloads/%d", providerID, workloadID), http.StatusSeeOther)
}

func (s *Server) handleWorkloadDelete(w http.ResponseWriter, r *http.Request) {
	providerID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	workloadID, err := strconv.ParseInt(r.PathValue("workloadID"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	workload, err := database.GetWorkload(ctx, s.db, workloadID)
	if err != nil || workload == nil || workload.IdentityProviderID != providerID {
		http.NotFound(w, r)
		return
	}

	if err := database.DeleteWorkload(ctx, s.db, workloadID); err != nil {
		log.Printf("error deleting workload: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.recordControlPlaneAudit(
		r,
		"delete",
		"workload",
		map[string]interface{}{"id": workload.ID},
		map[string]interface{}{"identity_provider_id": workload.IdentityProviderID, "name": workload.Name, "selector": string(workload.Selector)},
		nil,
		nil,
	)

	http.Redirect(w, r, fmt.Sprintf("/admin/providers/%d", providerID), http.StatusSeeOther)
}

func (s *Server) handleWorkloadLink(w http.ResponseWriter, r *http.Request) {
	providerID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	workloadID, err := strconv.ParseInt(r.PathValue("workloadID"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	workload, err := database.GetWorkload(ctx, s.db, workloadID)
	if err != nil || workload == nil || workload.IdentityProviderID != providerID {
		http.NotFound(w, r)
		return
	}

	appIDStr := r.FormValue("application_id")
	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/providers/%d/workloads/%d", providerID, workloadID), http.StatusSeeOther)
		return
	}

	if err := database.LinkApplicationWorkload(ctx, s.db, appID, workloadID); err != nil {
		log.Printf("error linking application to workload: %v", err)
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/providers/%d/workloads/%d", providerID, workloadID), http.StatusSeeOther)
}

func (s *Server) handleWorkloadUnlink(w http.ResponseWriter, r *http.Request) {
	providerID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	workloadID, err := strconv.ParseInt(r.PathValue("workloadID"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	workload, err := database.GetWorkload(ctx, s.db, workloadID)
	if err != nil || workload == nil || workload.IdentityProviderID != providerID {
		http.NotFound(w, r)
		return
	}

	appIDStr := r.FormValue("application_id")
	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/providers/%d/workloads/%d", providerID, workloadID), http.StatusSeeOther)
		return
	}

	if err := database.UnlinkApplicationWorkload(ctx, s.db, appID, workloadID); err != nil {
		log.Printf("error unlinking application from workload: %v", err)
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/providers/%d/workloads/%d", providerID, workloadID), http.StatusSeeOther)
}
