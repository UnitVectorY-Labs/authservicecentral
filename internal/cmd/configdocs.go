package cmd

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
)

// The page names are deliberately fixed so that a generated directory can be
// published as-is by any static file server.
var configDocsPageOrder = []string{
	"index.html",
	"configuration.html",
	"token-sources.html",
	"permissions.html",
	"roles.html",
	"resources.html",
	"management-permissions.html",
}

var configDocsPageSpecs = []struct {
	file   string
	title  string
	active string
}{
	{file: "index.html", title: "Configuration overview", active: "overview"},
	{file: "configuration.html", title: "Full safe configuration", active: "configuration"},
	{file: "token-sources.html", title: "Token sources", active: "token-sources"},
	{file: "permissions.html", title: "Permissions", active: "permissions"},
	{file: "roles.html", title: "Roles", active: "roles"},
	{file: "resources.html", title: "Resources", active: "resources"},
	{file: "management-permissions.html", title: "Management permission mappings", active: "management"},
}

//go:embed templates/config-docs/*.html
var configDocsTemplates embed.FS

type configDocsOptions struct {
	configPath string
	outputDir  string
}

// ConfigDocs renders the validated deployment authorization YAML as a set of
// static HTML pages. It intentionally loads the schema through config.Load so
// the command has exactly the same strict parsing and validation behavior as
// the runtime commands.
func ConfigDocs(args []string) error {
	op, err := parseConfigDocsOptions(args)
	if err != nil {
		return err
	}
	cfg, err := config.Load(op.configPath)
	if err != nil {
		return err
	}
	pages, err := renderConfigDocs(cfg)
	if err != nil {
		return err
	}
	if err := writeConfigDocs(op.outputDir, pages); err != nil {
		return err
	}
	fmt.Printf("wrote %d configuration documentation pages to %s\n", len(configDocsPageOrder), op.outputDir)
	return nil
}

func parseConfigDocsOptions(args []string) (configDocsOptions, error) {
	configPath := os.Getenv("SERVICEAUTH_CONFIG")
	if configPath == "" {
		configPath = "serviceauth.yaml"
	}
	outputDir := "config-docs"
	fs := flag.NewFlagSet("config-docs", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&configPath, "config", configPath, "deployment authorization YAML")
	fs.StringVar(&outputDir, "output-dir", outputDir, "directory for generated static HTML")
	// --output is a convenient spelling for callers that use the same option
	// across static documentation generators. Both options name a directory.
	fs.StringVar(&outputDir, "output", outputDir, "directory for generated static HTML")
	if err := fs.Parse(args); err != nil {
		return configDocsOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return configDocsOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if strings.TrimSpace(configPath) == "" {
		return configDocsOptions{}, errors.New("--config is required")
	}
	if strings.TrimSpace(outputDir) == "" {
		return configDocsOptions{}, errors.New("--output-dir is required")
	}
	return configDocsOptions{configPath: configPath, outputDir: outputDir}, nil
}

type configDocsView struct {
	PageTitle string
	Active    string
	Model     configDocsModel
}

type configDocsModel struct {
	Version               int
	Fingerprint           string
	SafeConfiguration     string
	Counts                configDocsCounts
	TokenSources          []tokenSourceDoc
	Permissions           []permissionDoc
	Roles                 []roleDoc
	Resources             []resourceDoc
	ManagementPermissions []managementPermissionDoc
}

type configDocsCounts struct {
	TokenSources          int
	Permissions           int
	Roles                 int
	Resources             int
	ManagementPermissions int
	ManagementRoutes      int
}

type tokenSourceDoc struct {
	Name             string
	Issuer           string
	KeyMode          string
	KeyDetails       string
	Algorithms       []string
	SubjectClaim     string
	Prefix           string
	Validation       []matcherDoc
	PropagatedClaims []propagatedClaimDoc
}

type matcherDoc struct {
	Scope     string
	Operation string
	Value     string
}

type propagatedClaimDoc struct {
	Claim string
	From  string
}

type permissionDoc struct {
	Name      string
	Resources []string
}

type roleDoc struct {
	Name        string
	Permissions []string
}

type resourceDoc struct {
	Name          string
	Relationships []relationshipDoc
	Inheritance   []inheritanceDoc
}

type relationshipDoc struct {
	Name        string
	Targets     []string
	Cardinality string
	Required    bool
}

type inheritanceDoc struct {
	Relationship string
	Permissions  []string
}

type managementPermissionDoc struct {
	Permission string
	Configured bool
	Resources  []string
	Roles      []string
	Routes     []managementRouteDoc
}

type managementRouteDoc struct {
	Method string
	Path   string
}

// These are the management guards attached to the existing API routes. They
// are kept here as documentation data; the runtime authorization remains in
// internal/api and this command never imports or changes that package.
var managementRoutes = []struct {
	method     string
	path       string
	permission string
}{
	{method: "POST", path: "/v1/manage/audiences", permission: "management.audiences.write"},
	{method: "GET", path: "/v1/manage/audiences", permission: "management.audiences.read"},
	{method: "GET", path: "/v1/manage/audiences/{id}", permission: "management.audiences.read"},
	{method: "PATCH", path: "/v1/manage/audiences/{id}", permission: "management.audiences.write"},
	{method: "DELETE", path: "/v1/manage/audiences/{id}", permission: "management.audiences.write"},
	{method: "POST", path: "/v1/manage/resources", permission: "management.resources.write"},
	{method: "GET", path: "/v1/manage/resources/{type}/{id}", permission: "management.resources.read"},
	{method: "PATCH", path: "/v1/manage/resources/{type}/{id}", permission: "management.resources.write"},
	{method: "DELETE", path: "/v1/manage/resources/{type}/{id}", permission: "management.resources.write"},
	{method: "PUT", path: "/v1/manage/resources/{type}/{id}/relationships/{relation}", permission: "management.resources.write"},
	{method: "DELETE", path: "/v1/manage/resources/{type}/{id}/relationships/{relation}", permission: "management.resources.write"},
	{method: "POST", path: "/v1/manage/groups", permission: "management.groups.write"},
	{method: "GET", path: "/v1/manage/groups/{id}", permission: "management.groups.read"},
	{method: "DELETE", path: "/v1/manage/groups/{id}", permission: "management.groups.write"},
	{method: "POST", path: "/v1/manage/groups/{id}/members", permission: "management.groups.write"},
	{method: "DELETE", path: "/v1/manage/groups/{id}/members", permission: "management.groups.write"},
	{method: "POST", path: "/v1/manage/grants", permission: "management.grants.write"},
	{method: "GET", path: "/v1/manage/grants", permission: "management.grants.read"},
	{method: "DELETE", path: "/v1/manage/grants/{id}", permission: "management.grants.write"},
}

func renderConfigDocs(cfg *config.Config) (map[string][]byte, error) {
	if cfg == nil {
		return nil, errors.New("configuration documentation requires a configuration")
	}
	fingerprint, err := cfg.Fingerprint()
	if err != nil {
		return nil, err
	}
	safeConfiguration, err := safeConfigurationJSON(cfg)
	if err != nil {
		return nil, err
	}
	model := buildConfigDocsModel(cfg, fingerprint, safeConfiguration)

	templates, err := template.New("config-docs").Funcs(template.FuncMap{
		"join": strings.Join,
	}).ParseFS(configDocsTemplates, "templates/config-docs/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse configuration documentation templates: %w", err)
	}
	pages := make(map[string][]byte, len(configDocsPageSpecs))
	for _, spec := range configDocsPageSpecs {
		var page bytes.Buffer
		view := configDocsView{PageTitle: spec.title, Active: spec.active, Model: model}
		if err := templates.ExecuteTemplate(&page, spec.file, view); err != nil {
			return nil, fmt.Errorf("render %s: %w", spec.file, err)
		}
		pages[spec.file] = page.Bytes()
	}
	return pages, nil
}

func writeConfigDocs(outputDir string, pages map[string][]byte) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create configuration documentation directory %s: %w", outputDir, err)
	}
	for _, name := range configDocsPageOrder {
		body, ok := pages[name]
		if !ok {
			return fmt.Errorf("configuration documentation page %q was not rendered", name)
		}
		path := filepath.Join(outputDir, name)
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return fmt.Errorf("write configuration documentation page %s: %w", path, err)
		}
	}
	return nil
}

func buildConfigDocsModel(cfg *config.Config, fingerprint, safeConfiguration string) configDocsModel {
	model := configDocsModel{
		Version:           cfg.Version,
		Fingerprint:       fingerprint,
		SafeConfiguration: safeConfiguration,
	}

	for _, name := range sortedConfigKeys(cfg.TokenSources) {
		source := cfg.TokenSources[name]
		algorithms := append([]string(nil), source.Algorithms...)
		sort.Strings(algorithms)
		doc := tokenSourceDoc{
			Name:         name,
			Issuer:       source.Issuer,
			KeyMode:      tokenSourceKeyMode(source.Keys),
			KeyDetails:   tokenSourceKeyDetails(source.Keys),
			Algorithms:   algorithms,
			SubjectClaim: source.Identity.SubjectClaim,
			Prefix:       source.Identity.Prefix,
		}
		if source.Validation.Audience != nil {
			doc.Validation = append(doc.Validation, matcherDoc{Scope: "audience", Operation: matcherOperation(*source.Validation.Audience), Value: matcherValue(*source.Validation.Audience)})
		}
		for _, claim := range sortedConfigKeys(source.Validation.Claims) {
			matcher := source.Validation.Claims[claim]
			doc.Validation = append(doc.Validation, matcherDoc{Scope: "claim: " + claim, Operation: matcherOperation(matcher), Value: matcherValue(matcher)})
		}
		for _, claim := range sortedConfigKeys(source.PropagateClaims) {
			doc.PropagatedClaims = append(doc.PropagatedClaims, propagatedClaimDoc{Claim: claim, From: source.PropagateClaims[claim].From})
		}
		model.TokenSources = append(model.TokenSources, doc)
	}

	for _, name := range sortedConfigKeys(cfg.Permissions) {
		resources := append([]string(nil), cfg.Permissions[name].Resources...)
		sort.Strings(resources)
		model.Permissions = append(model.Permissions, permissionDoc{Name: name, Resources: resources})
	}
	for _, name := range sortedConfigKeys(cfg.Roles) {
		permissions := append([]string(nil), cfg.Roles[name].Permissions...)
		sort.Strings(permissions)
		model.Roles = append(model.Roles, roleDoc{Name: name, Permissions: permissions})
	}
	for _, name := range sortedConfigKeys(cfg.Resources) {
		resource := cfg.Resources[name]
		doc := resourceDoc{Name: name}
		for _, relationName := range sortedConfigKeys(resource.Relationships) {
			relation := resource.Relationships[relationName]
			targets := append([]string(nil), relation.Targets...)
			sort.Strings(targets)
			doc.Relationships = append(doc.Relationships, relationshipDoc{Name: relationName, Targets: targets, Cardinality: relation.Cardinality, Required: relation.Required})
		}
		for _, inheritance := range resource.Inheritance {
			permissions := append([]string(nil), inheritance.Permissions...)
			sort.Strings(permissions)
			doc.Inheritance = append(doc.Inheritance, inheritanceDoc{Relationship: inheritance.Relationship, Permissions: permissions})
		}
		sort.SliceStable(doc.Inheritance, func(i, j int) bool {
			if doc.Inheritance[i].Relationship != doc.Inheritance[j].Relationship {
				return doc.Inheritance[i].Relationship < doc.Inheritance[j].Relationship
			}
			return strings.Join(doc.Inheritance[i].Permissions, "\x00") < strings.Join(doc.Inheritance[j].Permissions, "\x00")
		})
		model.Resources = append(model.Resources, doc)
	}
	model.ManagementPermissions = buildManagementPermissionDocs(cfg)
	model.Counts = countConfigDocs(model)
	return model
}

func countConfigDocs(model configDocsModel) configDocsCounts {
	routes := 0
	for _, permission := range model.ManagementPermissions {
		routes += len(permission.Routes)
	}
	return configDocsCounts{
		TokenSources:          len(model.TokenSources),
		Permissions:           len(model.Permissions),
		Roles:                 len(model.Roles),
		Resources:             len(model.Resources),
		ManagementPermissions: len(model.ManagementPermissions),
		ManagementRoutes:      routes,
	}
}

func buildManagementPermissionDocs(cfg *config.Config) []managementPermissionDoc {
	byPermission := make(map[string]*managementPermissionDoc)
	configuredMappings := cfg.Management.ManagementPermissionMap()
	for _, route := range managementRoutes {
		mappingKey := strings.TrimPrefix(route.permission, "management.")
		effectivePermission := route.permission
		if configured := configuredMappings[mappingKey]; configured != "" {
			effectivePermission = configured
		}
		doc := byPermission[effectivePermission]
		if doc == nil {
			doc = &managementPermissionDoc{Permission: effectivePermission}
			byPermission[effectivePermission] = doc
		}
		doc.Routes = append(doc.Routes, managementRouteDoc{Method: route.method, Path: route.path})
	}
	for name := range cfg.Permissions {
		if strings.HasPrefix(name, "management.") {
			if byPermission[name] == nil {
				byPermission[name] = &managementPermissionDoc{Permission: name}
			}
		}
	}
	for _, name := range sortedConfigKeys(byPermission) {
		doc := byPermission[name]
		permission, configured := cfg.Permissions[name]
		doc.Configured = configured
		if configured {
			doc.Resources = append([]string(nil), permission.Resources...)
			sort.Strings(doc.Resources)
		}
		for _, roleName := range sortedConfigKeys(cfg.Roles) {
			if containsString(cfg.Roles[roleName].Permissions, name) {
				doc.Roles = append(doc.Roles, roleName)
			}
		}
		sort.Slice(doc.Routes, func(i, j int) bool {
			if doc.Routes[i].Path != doc.Routes[j].Path {
				return doc.Routes[i].Path < doc.Routes[j].Path
			}
			return doc.Routes[i].Method < doc.Routes[j].Method
		})
	}
	result := make([]managementPermissionDoc, 0, len(byPermission))
	for _, name := range sortedConfigKeys(byPermission) {
		result = append(result, *byPermission[name])
	}
	return result
}

func tokenSourceKeyMode(keys config.Keys) string {
	switch {
	case keys.Discovery:
		return "discovery"
	case keys.JWKSURL != "":
		return "jwks_url"
	case len(keys.JWKS) > 0:
		return "inline jwks"
	case keys.PublicKey != "":
		return "public_key"
	default:
		return "not configured"
	}
}

func tokenSourceKeyDetails(keys config.Keys) string {
	switch tokenSourceKeyMode(keys) {
	case "jwks_url":
		return keys.JWKSURL
	case "inline jwks":
		return "inline JWK set configured"
	case "public_key":
		return "PEM public key configured"
	default:
		return "issuer discovery enabled"
	}
}

func matcherOperation(m config.Matcher) string {
	switch {
	case m.Exists != nil:
		return "exists"
	case m.Equals != nil:
		return "equals"
	case m.NotEquals != nil:
		return "not equals"
	case m.OneOf != nil:
		return "one of"
	case m.AnyOf != nil:
		return "any of"
	case m.Prefix != "":
		return "prefix"
	case m.Suffix != "":
		return "suffix"
	case m.Regex != "":
		return "regex"
	case m.Contains != nil:
		return "contains"
	default:
		return "not configured"
	}
}

func matcherValue(m config.Matcher) string {
	var value any
	switch {
	case m.Exists != nil:
		value = *m.Exists
	case m.Equals != nil:
		value = m.Equals
	case m.NotEquals != nil:
		value = m.NotEquals
	case m.OneOf != nil:
		value = m.OneOf
	case m.AnyOf != nil:
		value = m.AnyOf
	case m.Prefix != "":
		value = m.Prefix
	case m.Suffix != "":
		value = m.Suffix
	case m.Regex != "":
		value = m.Regex
	case m.Contains != nil:
		value = m.Contains
	default:
		return ""
	}
	return jsonValue(value)
}

func safeConfigurationJSON(cfg *config.Config) (string, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("encode safe configuration: %w", err)
	}
	var value any
	if err := json.Unmarshal(b, &value); err != nil {
		return "", fmt.Errorf("prepare safe configuration: %w", err)
	}
	value = redactConfigurationValue("", value)
	b, err = json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", fmt.Errorf("format safe configuration: %w", err)
	}
	return string(b), nil
}

func redactConfigurationValue(key string, value any) any {
	if sensitiveConfigurationKey(key) {
		return "[REDACTED]"
	}
	if stringValue, ok := value.(string); ok && containsPrivatePEM(stringValue) {
		return "[REDACTED]"
	}
	switch typed := value.(type) {
	case map[string]any:
		for childKey, childValue := range typed {
			typed[childKey] = redactConfigurationValue(childKey, childValue)
		}
	case []any:
		for i, childValue := range typed {
			typed[i] = redactConfigurationValue(key, childValue)
		}
	}
	return value
}

func sensitiveConfigurationKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
	switch normalized {
	case "d", "p", "q", "dp", "dq", "qi", "oth", "k", "secret", "password", "token", "access_token", "refresh_token", "client_secret", "private_key", "private_key_pem", "public_key", "public_jwk", "jwks", "credential", "credentials", "api_key", "signing_key":
		return true
	}
	return strings.Contains(normalized, "secret") || strings.Contains(normalized, "password") || strings.Contains(normalized, "private") || strings.HasSuffix(normalized, "_token")
}

func containsPrivatePEM(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "BEGIN PRIVATE KEY") || strings.Contains(upper, "BEGIN RSA PRIVATE KEY") || strings.Contains(upper, "BEGIN EC PRIVATE KEY")
}

func jsonValue(value any) string {
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(b)
}

func sortedConfigKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
