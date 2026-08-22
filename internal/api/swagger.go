package api

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// swaggerAssets is the pinned Swagger UI distribution served locally so the
// documentation page remains usable without a browser reaching the network.
//
//go:embed static/*
var swaggerAssets embed.FS

var swaggerStaticFS, _ = fs.Sub(swaggerAssets, "static")

var (
	openAPISpecMu sync.RWMutex
	openAPISpec   []byte
)

// SetOpenAPISpec supplies the canonical embedded specification to servers
// created by the executable. Tests and embedders can instead set
// Options.OpenAPISpec directly.
func SetOpenAPISpec(spec []byte) {
	openAPISpecMu.Lock()
	openAPISpec = append([]byte(nil), spec...)
	openAPISpecMu.Unlock()
}

func configuredOpenAPISpec(options Options) []byte {
	if len(options.OpenAPISpec) > 0 {
		return append([]byte(nil), options.OpenAPISpec...)
	}
	openAPISpecMu.RLock()
	defer openAPISpecMu.RUnlock()
	return append([]byte(nil), openAPISpec...)
}

func (s *Server) swagger(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(swaggerHTML))
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	spec := configuredOpenAPISpec(s.options)
	if len(spec) == 0 {
		s.writeError(w, r, Error(http.StatusServiceUnavailable, "openapi_unavailable", "the OpenAPI specification is not embedded"))
		return
	}
	if s.options.Issuer != "" {
		spec = specWithIssuer(spec, s.options.Issuer)
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="openapi.yaml"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(spec)
}

// specWithIssuer replaces the top-level servers block of the embedded
// specification with the deployment's configured issuer so the served
// document points at the canonical host instead of the local default.
// A spec without a top-level servers block is returned unchanged.
func specWithIssuer(spec []byte, issuer string) []byte {
	lines := strings.Split(string(spec), "\n")
	start := -1
	for i, line := range lines {
		if line == "servers:" {
			start = i
			break
		}
	}
	if start == -1 {
		return spec
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		line := lines[i]
		if line != "" && line[0] != ' ' && line[0] != '\t' && line[0] != '#' {
			end = i
			break
		}
	}
	replacement := serversBlock(issuer)
	if replacement == nil {
		return spec
	}
	result := make([]string, 0, len(lines)-(end-start)+len(replacement))
	result = append(result, lines[:start]...)
	result = append(result, replacement...)
	result = append(result, lines[end:]...)
	return []byte(strings.Join(result, "\n"))
}

func serversBlock(issuer string) []string {
	type openAPIServer struct {
		URL         string `yaml:"url"`
		Description string `yaml:"description"`
	}
	type openAPIServers struct {
		Servers []openAPIServer `yaml:"servers"`
	}
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	err := encoder.Encode(openAPIServers{Servers: []openAPIServer{{URL: issuer, Description: "Deployment base URL"}}})
	_ = encoder.Close()
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
}

// Swagger UI is a static shell backed by the pinned, embedded distribution.
const swaggerHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>authservicecentral API</title>
  <link rel="stylesheet" href="/swagger-ui/swagger-ui.css">
  <style>body { margin: 0; background: #fafafa; } .topbar { display: none; }</style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/swagger-ui/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function () {
      window.ui = SwaggerUIBundle({
        url: '/openapi.yaml',
        dom_id: '#swagger-ui',
        deepLinking: true,
        displayRequestDuration: true,
        filter: true,
        persistAuthorization: true,
        tryItOutEnabled: false,
        presets: [SwaggerUIBundle.presets.apis]
      });
    };
  </script>
</body>
</html>`
