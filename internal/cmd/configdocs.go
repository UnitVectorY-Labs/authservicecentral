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

// These are the fixed landing and index pages. Role and permission detail
// pages are added from the validated configuration.
var configDocsPageOrder = []string{
	"index.html",
	"permissions.html",
	"roles.html",
	"resources.html",
	"token-sources.html",
	"management-permissions.html",
}

var configDocsPageSpecs = []struct {
	file   string
	title  string
	active string
}{
	{file: "index.html", title: "Authorization guide", active: "overview"},
	{file: "permissions.html", title: "Permissions", active: "permissions"},
	{file: "roles.html", title: "Roles", active: "roles"},
	{file: "resources.html", title: "Resources", active: "resources"},
	{file: "token-sources.html", title: "Identity sources", active: "token-sources"},
	{file: "management-permissions.html", title: "Management permission mappings", active: "management"},
}

//go:embed templates/config-docs/*.html
var configDocsTemplates embed.FS

type configDocsOptions struct {
	configPath string
	outputDir  string
}

// ConfigDocs builds an application-facing authorization guide from the
// validated deployment YAML. It intentionally loads the schema through
// config.Load so the command has exactly the same strict parsing and validation
// behavior as the runtime commands.
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
	fmt.Printf("wrote %d application authorization documentation pages to %s\n", len(pages), op.outputDir)
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
	PageTitle  string
	Active     string
	Model      configDocsModel
	Permission *permissionDoc
	Role       *roleDoc
	SearchJSON string
}

type configDocsModel struct {
	Version               int
	Fingerprint           string
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
	Name             string
	Filename         string
	Resources        []namedLinkDoc
	Roles            []namedLinkDoc
	InheritedThrough []permissionInheritanceDoc
	ManagementRoutes []managementRouteDoc
}

type roleDoc struct {
	Name           string
	Filename       string
	Permissions    []namedLinkDoc
	ResourceAccess []roleResourceAccessDoc
}

type namedLinkDoc struct {
	Name string
	Href string
}

type permissionInheritanceDoc struct {
	Resource     string
	ResourceHref string
	Relationship string
}

type roleResourceAccessDoc struct {
	Resource     string
	ResourceHref string
	Permissions  []namedLinkDoc
}

type resourceDoc struct {
	Name          string
	Href          string
	Permissions   []namedLinkDoc
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
	Permissions  []namedLinkDoc
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

type configDocsSearchItem struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Summary  string `json:"summary"`
	Href     string `json:"href"`
	Keywords string `json:"keywords"`
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
	model := buildConfigDocsModel(cfg, fingerprint)
	searchJSON, err := json.Marshal(buildConfigDocsSearchIndex(model))
	if err != nil {
		return nil, fmt.Errorf("encode configuration documentation search index: %w", err)
	}

	templates, err := template.New("config-docs").Funcs(template.FuncMap{
		"join": strings.Join,
	}).ParseFS(configDocsTemplates, "templates/config-docs/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse configuration documentation templates: %w", err)
	}
	pages := make(map[string][]byte, len(configDocsPageSpecs)+len(model.Permissions)+len(model.Roles))
	for _, spec := range configDocsPageSpecs {
		var page bytes.Buffer
		view := configDocsView{PageTitle: spec.title, Active: spec.active, Model: model, SearchJSON: string(searchJSON)}
		if err := templates.ExecuteTemplate(&page, spec.file, view); err != nil {
			return nil, fmt.Errorf("render %s: %w", spec.file, err)
		}
		pages[spec.file] = page.Bytes()
	}
	for i := range model.Permissions {
		permission := &model.Permissions[i]
		var page bytes.Buffer
		view := configDocsView{PageTitle: permission.Name + " permission", Active: "permissions", Model: model, Permission: permission, SearchJSON: string(searchJSON)}
		if err := templates.ExecuteTemplate(&page, "permission.html", view); err != nil {
			return nil, fmt.Errorf("render %s: %w", permission.Filename, err)
		}
		pages[permission.Filename] = page.Bytes()
	}
	for i := range model.Roles {
		role := &model.Roles[i]
		var page bytes.Buffer
		view := configDocsView{PageTitle: role.Name + " role", Active: "roles", Model: model, Role: role, SearchJSON: string(searchJSON)}
		if err := templates.ExecuteTemplate(&page, "role.html", view); err != nil {
			return nil, fmt.Errorf("render %s: %w", role.Filename, err)
		}
		pages[role.Filename] = page.Bytes()
	}
	return pages, nil
}

func writeConfigDocs(outputDir string, pages map[string][]byte) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create configuration documentation directory %s: %w", outputDir, err)
	}
	// Older versions generated a raw, redacted configuration page. Remove that
	// known generated artifact so regenerating into an existing output directory
	// cannot accidentally keep publishing it.
	obsoleteConfigurationPage := filepath.Join(outputDir, "configuration.html")
	if err := os.Remove(obsoleteConfigurationPage); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove obsolete configuration documentation page %s: %w", obsoleteConfigurationPage, err)
	}
	for _, pattern := range []string{"permission-*.html", "role-*.html"} {
		matches, err := filepath.Glob(filepath.Join(outputDir, pattern))
		if err != nil {
			return fmt.Errorf("find stale configuration documentation pages matching %s: %w", pattern, err)
		}
		for _, match := range matches {
			if _, stillGenerated := pages[filepath.Base(match)]; stillGenerated {
				continue
			}
			if err := os.Remove(match); err != nil {
				return fmt.Errorf("remove stale configuration documentation page %s: %w", match, err)
			}
		}
	}
	names := sortedConfigKeys(pages)
	for _, name := range names {
		body := pages[name]
		path := filepath.Join(outputDir, name)
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return fmt.Errorf("write configuration documentation page %s: %w", path, err)
		}
	}
	return nil
}

func buildConfigDocsModel(cfg *config.Config, fingerprint string) configDocsModel {
	model := configDocsModel{
		Version:     cfg.Version,
		Fingerprint: fingerprint,
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
		doc := permissionDoc{Name: name, Filename: permissionFilename(name)}
		for _, resource := range resources {
			doc.Resources = append(doc.Resources, namedLinkDoc{Name: resource, Href: resourceHref(resource)})
		}
		for _, role := range sortedConfigKeys(cfg.Roles) {
			if containsString(cfg.Roles[role].Permissions, name) {
				doc.Roles = append(doc.Roles, namedLinkDoc{Name: role, Href: roleFilename(role)})
			}
		}
		for _, resourceName := range sortedConfigKeys(cfg.Resources) {
			for _, inheritance := range cfg.Resources[resourceName].Inheritance {
				if containsString(inheritance.Permissions, name) {
					doc.InheritedThrough = append(doc.InheritedThrough, permissionInheritanceDoc{Resource: resourceName, ResourceHref: resourceHref(resourceName), Relationship: inheritance.Relationship})
				}
			}
		}
		model.Permissions = append(model.Permissions, doc)
	}
	for _, name := range sortedConfigKeys(cfg.Roles) {
		permissions := append([]string(nil), cfg.Roles[name].Permissions...)
		sort.Strings(permissions)
		doc := roleDoc{Name: name, Filename: roleFilename(name)}
		for _, permission := range permissions {
			doc.Permissions = append(doc.Permissions, namedLinkDoc{Name: permission, Href: permissionFilename(permission)})
		}
		for _, resourceName := range resourceNamesForRole(cfg, name) {
			access := roleResourceAccessDoc{Resource: resourceName, ResourceHref: resourceHref(resourceName)}
			for _, permission := range permissions {
				if containsString(cfg.Permissions[permission].Resources, resourceName) {
					access.Permissions = append(access.Permissions, namedLinkDoc{Name: permission, Href: permissionFilename(permission)})
				}
			}
			doc.ResourceAccess = append(doc.ResourceAccess, access)
		}
		model.Roles = append(model.Roles, doc)
	}
	for _, name := range sortedConfigKeys(cfg.Resources) {
		resource := cfg.Resources[name]
		doc := resourceDoc{Name: name, Href: "resources.html#resource-" + name}
		for _, permissionName := range sortedConfigKeys(cfg.Permissions) {
			if containsString(cfg.Permissions[permissionName].Resources, name) {
				doc.Permissions = append(doc.Permissions, namedLinkDoc{Name: permissionName, Href: permissionFilename(permissionName)})
			}
		}
		for _, relationName := range sortedConfigKeys(resource.Relationships) {
			relation := resource.Relationships[relationName]
			targets := append([]string(nil), relation.Targets...)
			sort.Strings(targets)
			doc.Relationships = append(doc.Relationships, relationshipDoc{Name: relationName, Targets: targets, Cardinality: relation.Cardinality, Required: relation.Required})
		}
		for _, inheritance := range resource.Inheritance {
			permissions := append([]string(nil), inheritance.Permissions...)
			sort.Strings(permissions)
			inheritanceDoc := inheritanceDoc{Relationship: inheritance.Relationship}
			for _, permission := range permissions {
				inheritanceDoc.Permissions = append(inheritanceDoc.Permissions, namedLinkDoc{Name: permission, Href: permissionFilename(permission)})
			}
			doc.Inheritance = append(doc.Inheritance, inheritanceDoc)
		}
		sort.SliceStable(doc.Inheritance, func(i, j int) bool {
			if doc.Inheritance[i].Relationship != doc.Inheritance[j].Relationship {
				return doc.Inheritance[i].Relationship < doc.Inheritance[j].Relationship
			}
			return namedLinksKey(doc.Inheritance[i].Permissions) < namedLinksKey(doc.Inheritance[j].Permissions)
		})
		model.Resources = append(model.Resources, doc)
	}
	model.ManagementPermissions = buildManagementPermissionDocs(cfg)
	for i := range model.Permissions {
		for _, management := range model.ManagementPermissions {
			if management.Permission == model.Permissions[i].Name {
				model.Permissions[i].ManagementRoutes = append([]managementRouteDoc(nil), management.Routes...)
			}
		}
	}
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

func permissionFilename(name string) string {
	return "permission-" + name + ".html"
}

func roleFilename(name string) string {
	return "role-" + name + ".html"
}

func resourceHref(name string) string {
	if name == "audience" {
		return "index.html#how-access-works"
	}
	return "resources.html#resource-" + name
}

func namedLinksKey(links []namedLinkDoc) string {
	names := make([]string, 0, len(links))
	for _, link := range links {
		names = append(names, link.Name)
	}
	return strings.Join(names, "\x00")
}

func namedLinksText(links []namedLinkDoc) string {
	names := make([]string, 0, len(links))
	for _, link := range links {
		names = append(names, link.Name)
	}
	return strings.Join(names, " ")
}

func resourceNamesForRole(cfg *config.Config, roleName string) []string {
	resourceSet := make(map[string]struct{})
	for _, permissionName := range cfg.Roles[roleName].Permissions {
		for _, resourceName := range cfg.Permissions[permissionName].Resources {
			resourceSet[resourceName] = struct{}{}
		}
	}
	return sortedConfigKeys(resourceSet)
}

func buildConfigDocsSearchIndex(model configDocsModel) []configDocsSearchItem {
	items := make([]configDocsSearchItem, 0, len(model.Permissions)+len(model.Roles)+len(model.Resources)+len(model.TokenSources))
	for _, permission := range model.Permissions {
		resources := namedLinksText(permission.Resources)
		roles := namedLinksText(permission.Roles)
		items = append(items, configDocsSearchItem{
			Type:     "Permission",
			Name:     permission.Name,
			Summary:  "Applies to " + humanList(permission.Resources, "resource type", "resource types"),
			Href:     permission.Filename,
			Keywords: resources + " " + roles,
		})
	}
	for _, role := range model.Roles {
		items = append(items, configDocsSearchItem{
			Type:     "Role",
			Name:     role.Name,
			Summary:  humanList(role.Permissions, "permission", "permissions"),
			Href:     role.Filename,
			Keywords: namedLinksText(role.Permissions) + " " + roleResourceKeywords(role.ResourceAccess),
		})
	}
	for _, resource := range model.Resources {
		items = append(items, configDocsSearchItem{
			Type:     "Resource",
			Name:     resource.Name,
			Summary:  humanList(resource.Permissions, "applicable permission", "applicable permissions"),
			Href:     resource.Href,
			Keywords: namedLinksText(resource.Permissions),
		})
	}
	for _, source := range model.TokenSources {
		items = append(items, configDocsSearchItem{
			Type:     "Identity source",
			Name:     source.Name,
			Summary:  "Trusts " + source.Issuer,
			Href:     "token-sources.html#source-" + source.Name,
			Keywords: source.Issuer + " " + source.Prefix + " " + source.SubjectClaim,
		})
	}
	return items
}

func humanList(items []namedLinkDoc, singular, plural string) string {
	if len(items) == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", len(items), plural)
}

func roleResourceKeywords(resources []roleResourceAccessDoc) string {
	values := make([]string, 0, len(resources))
	for _, resource := range resources {
		values = append(values, resource.Resource)
	}
	return strings.Join(values, " ")
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
