package web

import (
	"embed"
	"io/fs"
	"net/http"
)

// staticFS contains the static files (htmx, css, etc.)
//
//go:embed static/*
var staticFS embed.FS

// StaticFS returns the embedded static file system
func StaticFS() http.FileSystem {
	sub, _ := fs.Sub(staticFS, "static")
	return http.FS(sub)
}
