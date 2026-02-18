package web

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/credential"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

//go:embed templates/*.html templates/partials/*.html
var templateFS embed.FS

// pageData is the common data passed to every template
type pageData struct {
	Username string
	Nav      string
	Flash    string
	Error    string
}

func newPageData(r *http.Request, nav string) pageData {
	return pageData{
		Username: getUsername(r),
		Nav:      nav,
	}
}

// parseTemplates parses the base layout with a named page template
func parseTemplates(names ...string) *template.Template {
	files := []string{"templates/base.html", "templates/partials/header.html", "templates/partials/footer.html", "templates/partials/flash.html"}
	files = append(files, names...)
	return template.Must(template.ParseFS(templateFS, files...))
}

// renderPage renders a full page or just the #main content depending on the HX-Request header
func renderPage(w http.ResponseWriter, r *http.Request, tmpl *template.Template, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" {
		// Partial render: just the content block
		if err := tmpl.ExecuteTemplate(w, "content", data); err != nil {
			log.Printf("error rendering partial template: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}
	// Full page render
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("error rendering template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Templates (parsed once)
var (
	loginTmpl     *template.Template
	homeTmpl      *template.Template
	appsTmpl      *template.Template
	appsNewTmpl   *template.Template
	appDetailTmpl *template.Template
)

func init() {
	loginTmpl = template.Must(template.ParseFS(templateFS, "templates/login.html"))
	homeTmpl = parseTemplates("templates/home.html")
	appsTmpl = parseTemplates("templates/apps_list.html")
	appsNewTmpl = parseTemplates("templates/apps_new.html")
	appDetailTmpl = parseTemplates("templates/apps_detail.html")
}

var subjectPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// --- Login ---

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// If already authenticated, redirect to home
	if _, err := parseSessionCookie(s.sessionSecret, r); err == nil {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}

	data := struct{ Error string }{}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTmpl.Execute(w, data)
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		data := struct{ Error string }{Error: "Username and password are required."}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnprocessableEntity)
		loginTmpl.Execute(w, data)
		return
	}

	ctx := r.Context()

	// Look up the user
	user, err := database.LookupUserByUsername(ctx, s.db, username)
	if err != nil {
		log.Printf("error looking up user: %v", err)
		data := struct{ Error string }{Error: "An internal error occurred."}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		loginTmpl.Execute(w, data)
		return
	}

	// Bootstrap admin: if user doesn't exist and username is "admin" and bootstrap password is set
	if user == nil && username == "admin" && s.cfg.BootstrapAdminPassword != "" {
		if password == s.cfg.BootstrapAdminPassword {
			hash, err := credential.HashSecret(password)
			if err != nil {
				log.Printf("error hashing password: %v", err)
				data := struct{ Error string }{Error: "An internal error occurred."}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusInternalServerError)
				loginTmpl.Execute(w, data)
				return
			}
			user, err = database.CreateUser(ctx, s.db, "admin", hash)
			if err != nil {
				log.Printf("error creating bootstrap admin: %v", err)
				data := struct{ Error string }{Error: "An internal error occurred."}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusInternalServerError)
				loginTmpl.Execute(w, data)
				return
			}
			log.Printf("bootstrap admin user created")
		}
	}

	if user == nil {
		data := struct{ Error string }{Error: "Invalid username or password."}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnprocessableEntity)
		loginTmpl.Execute(w, data)
		return
	}

	if user.Locked {
		data := struct{ Error string }{Error: "Account is locked."}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		loginTmpl.Execute(w, data)
		return
	}

	// Verify password
	if !credential.VerifySecret(password, user.PasswordHash) {
		data := struct{ Error string }{Error: "Invalid username or password."}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnprocessableEntity)
		loginTmpl.Execute(w, data)
		return
	}

	// Update last login
	if err := database.UpdateUserLastLogin(ctx, s.db, user.ID); err != nil {
		log.Printf("error updating last login: %v", err)
	}

	// Set session cookie
	http.SetCookie(w, createSessionCookie(s.sessionSecret, user.Username))
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// --- Logout ---

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, clearSessionCookie())
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// --- Admin Home ---

func (s *Server) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	data := newPageData(r, "home")
	renderPage(w, r, homeTmpl, data)
}

// --- Applications List ---

const appsPerPage = 20

type appsListData struct {
	pageData
	Apps       []database.ApplicationListItem
	Search     string
	Page       int
	TotalPages int
	Total      int
	StartItem  int
	EndItem    int
	PrevPage   int
	NextPage   int
}

func (s *Server) handleAppsList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	search := r.URL.Query().Get("q")

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}

	offset := (page - 1) * appsPerPage

	total, err := database.CountApplications(ctx, s.db, search)
	if err != nil {
		log.Printf("error counting applications: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	apps, err := database.ListApplications(ctx, s.db, search, appsPerPage, offset)
	if err != nil {
		log.Printf("error listing applications: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	totalPages := (total + appsPerPage - 1) / appsPerPage
	if totalPages < 1 {
		totalPages = 1
	}

	startItem := offset + 1
	endItem := offset + len(apps)
	if total == 0 {
		startItem = 0
	}

	data := appsListData{
		pageData:   newPageData(r, "apps"),
		Apps:        apps,
		Search:     search,
		Page:       page,
		TotalPages: totalPages,
		Total:      total,
		StartItem:  startItem,
		EndItem:    endItem,
		PrevPage:   page - 1,
		NextPage:   page + 1,
	}

	renderPage(w, r, appsTmpl, data)
}

// --- New Application ---

type appsNewData struct {
	pageData
	Subject     string
	Description string
	AppType     string
}

func (s *Server) handleAppsNew(w http.ResponseWriter, r *http.Request) {
	data := appsNewData{
		pageData: newPageData(r, "apps"),
		AppType:  "service",
	}
	renderPage(w, r, appsNewTmpl, data)
}

func (s *Server) handleAppsCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	subject := strings.TrimSpace(r.FormValue("subject"))
	description := strings.TrimSpace(r.FormValue("description"))
	appType := r.FormValue("app_type")

	renderError := func(msg string) {
		data := appsNewData{
			pageData:    newPageData(r, "apps"),
			Subject:     subject,
			Description: description,
			AppType:     appType,
		}
		data.Error = msg
		w.WriteHeader(http.StatusUnprocessableEntity)
		renderPage(w, r, appsNewTmpl, data)
	}

	if subject == "" {
		renderError("Subject is required.")
		return
	}
	if !subjectPattern.MatchString(subject) {
		renderError("Subject may only contain letters, numbers, dots, hyphens, and underscores.")
		return
	}
	if appType != "service" && appType != "admin" && appType != "user_agent" {
		renderError("Invalid application type.")
		return
	}

	ctx := r.Context()
	_, err := database.CreateApplication(ctx, s.db, subject, description, appType)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			renderError("An application with that subject already exists.")
			return
		}
		log.Printf("error creating application: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/apps/"+subject, http.StatusSeeOther)
}

// --- Application Detail ---

type appDetailData struct {
	pageData
	App             database.ApplicationDetail
	Tab             string
	Scopes          []database.ApplicationScope
	Credentials     []database.ApplicationCredential
	ActiveCredCount int
	CreatedSecret   string
	CreatedClientID string
	OutboundAuths   []database.AuthorizationListItem
	InboundAuths    []database.AuthorizationListItem
	Workloads       []database.ApplicationWorkloadItem
}

func (s *Server) handleAppDetail(w http.ResponseWriter, r *http.Request) {
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

	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "overview"
	}

	data := appDetailData{
		pageData: newPageData(r, "apps"),
		App:      *app,
		Tab:      tab,
	}

	switch tab {
	case "scopes":
		scopes, err := database.ListApplicationScopes(ctx, s.db, app.ID)
		if err != nil {
			log.Printf("error listing scopes: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		data.Scopes = scopes
	case "credentials":
		creds, err := database.ListApplicationCredentials(ctx, s.db, app.ID)
		if err != nil {
			log.Printf("error listing credentials: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		data.Credentials = creds
		activeCount, err := database.CountActiveCredentials(ctx, s.db, app.ID)
		if err != nil {
			log.Printf("error counting active credentials: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		data.ActiveCredCount = activeCount
	case "authorizations":
		outbound, err := database.ListOutboundAuthorizations(ctx, s.db, app.ID)
		if err != nil {
			log.Printf("error listing outbound authorizations: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		data.OutboundAuths = outbound
		inbound, err := database.ListInboundAuthorizations(ctx, s.db, app.ID)
		if err != nil {
			log.Printf("error listing inbound authorizations: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		data.InboundAuths = inbound
	}

	renderPage(w, r, appDetailTmpl, data)
}

// --- Update Application ---

func (s *Server) handleAppUpdate(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

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

	description := strings.TrimSpace(r.FormValue("description"))
	locked := r.FormValue("locked") == "true"

	if err := database.UpdateApplication(ctx, s.db, app.ID, description, locked); err != nil {
		log.Printf("error updating application: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/apps/"+subject+"?tab=overview", http.StatusSeeOther)
}

// --- Scope Create ---

func (s *Server) handleScopeCreate(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

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

	scope := strings.TrimSpace(r.FormValue("scope"))
	description := strings.TrimSpace(r.FormValue("description"))

	if scope == "" {
		http.Redirect(w, r, "/admin/apps/"+subject+"?tab=scopes", http.StatusSeeOther)
		return
	}

	if err := database.CreateApplicationScope(ctx, s.db, app.ID, scope, description); err != nil {
		log.Printf("error creating scope: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/apps/"+subject+"?tab=scopes", http.StatusSeeOther)
}

// --- Scope Delete ---

func (s *Server) handleScopeDelete(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

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

	scope := r.FormValue("scope")
	if scope == "" {
		http.Redirect(w, r, "/admin/apps/"+subject+"?tab=scopes", http.StatusSeeOther)
		return
	}

	if err := database.DeleteApplicationScope(ctx, s.db, app.ID, scope); err != nil {
		log.Printf("error deleting scope: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/apps/"+subject+"?tab=scopes", http.StatusSeeOther)
}

// --- Credential Create ---

func (s *Server) handleCredentialCreate(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

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

	activeCount, err := database.CountActiveCredentials(ctx, s.db, app.ID)
	if err != nil {
		log.Printf("error counting active credentials: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if activeCount >= 2 {
		http.Redirect(w, r, "/admin/apps/"+subject+"?tab=credentials", http.StatusSeeOther)
		return
	}

	// Generate client_id (16 bytes = 32 hex chars)
	clientIDBytes := make([]byte, 16)
	if _, err := rand.Read(clientIDBytes); err != nil {
		log.Printf("error generating client_id: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	clientID := hex.EncodeToString(clientIDBytes)

	// Generate client_secret (32 bytes = 64 hex chars)
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		log.Printf("error generating client_secret: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	clientSecret := hex.EncodeToString(secretBytes)

	secretHash, err := credential.HashSecret(clientSecret)
	if err != nil {
		log.Printf("error hashing secret: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	label := strings.TrimSpace(r.FormValue("label"))
	if _, err := database.CreateApplicationCredential(ctx, s.db, app.ID, clientID, secretHash, label); err != nil {
		log.Printf("error creating credential: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Re-fetch data for display with the created secret
	creds, err := database.ListApplicationCredentials(ctx, s.db, app.ID)
	if err != nil {
		log.Printf("error listing credentials: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	newActiveCount, err := database.CountActiveCredentials(ctx, s.db, app.ID)
	if err != nil {
		log.Printf("error counting active credentials: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Re-fetch app detail for updated timestamps
	app, _ = database.GetApplicationDetail(ctx, s.db, subject)

	data := appDetailData{
		pageData:        newPageData(r, "apps"),
		App:             *app,
		Tab:             "credentials",
		Credentials:     creds,
		ActiveCredCount: newActiveCount,
		CreatedSecret:   clientSecret,
		CreatedClientID: clientID,
	}
	renderPage(w, r, appDetailTmpl, data)
}

// --- Credential Disable ---

func (s *Server) handleCredentialDisable(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

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

	credIDStr := r.FormValue("credential_id")
	credID, err := strconv.ParseInt(credIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if err := database.DisableApplicationCredential(ctx, s.db, credID); err != nil {
		log.Printf("error disabling credential: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s?tab=credentials", subject), http.StatusSeeOther)
}

// StaticAdminFS returns the embedded static file system for admin templates
func StaticAdminFS() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}
