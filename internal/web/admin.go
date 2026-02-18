package web

import (
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strconv"

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
	loginTmpl *template.Template
	homeTmpl  *template.Template
	appsTmpl  *template.Template
)

func init() {
	loginTmpl = template.Must(template.ParseFS(templateFS, "templates/login.html"))
	homeTmpl = parseTemplates("templates/home.html")
	appsTmpl = parseTemplates("templates/apps_list.html")
}

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

// StaticAdminFS returns the embedded static file system for admin templates
func StaticAdminFS() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}
