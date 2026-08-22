// Package config loads and validates the deployment authorization schema.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const Version = 1

var identifierRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
var permissionRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
var reservedTypes = map[string]bool{"principal": true, "group": true, "audience": true}
var reservedClaims = map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true, "act": true}
var algorithms = map[string]bool{"RS256": true, "RS384": true, "RS512": true, "ES256": true, "ES384": true, "ES512": true}

type Config struct {
	Version      int                    `yaml:"version" json:"version"`
	TokenSources map[string]TokenSource `yaml:"token_sources" json:"token_sources"`
	Permissions  map[string]Permission  `yaml:"permissions" json:"permissions"`
	Roles        map[string]Role        `yaml:"roles" json:"roles"`
	Resources    map[string]Resource    `yaml:"resources" json:"resources"`
}

type TokenSource struct {
	Issuer          string                 `yaml:"issuer" json:"issuer"`
	Keys            Keys                   `yaml:"keys" json:"keys"`
	Algorithms      []string               `yaml:"algorithms" json:"algorithms"`
	Identity        Identity               `yaml:"identity" json:"identity"`
	Validation      Validation             `yaml:"validation,omitempty" json:"validation,omitempty"`
	PropagateClaims map[string]Propagation `yaml:"propagate_claims,omitempty" json:"propagate_claims,omitempty"`
}

type Keys struct {
	Discovery bool           `yaml:"discovery,omitempty" json:"discovery,omitempty"`
	JWKSURL   string         `yaml:"jwks_url,omitempty" json:"jwks_url,omitempty"`
	JWKS      map[string]any `yaml:"jwks,omitempty" json:"jwks,omitempty"`
	PublicKey string         `yaml:"public_key,omitempty" json:"public_key,omitempty"`
}

type Identity struct {
	SubjectClaim string `yaml:"subject_claim" json:"subject_claim"`
	Prefix       string `yaml:"prefix" json:"prefix"`
}

type Validation struct {
	Audience *Matcher           `yaml:"audience,omitempty" json:"audience,omitempty"`
	Claims   map[string]Matcher `yaml:"claims,omitempty" json:"claims,omitempty"`
}

type Matcher struct {
	Exists    *bool  `yaml:"exists,omitempty" json:"exists,omitempty"`
	Equals    any    `yaml:"equals,omitempty" json:"equals,omitempty"`
	NotEquals any    `yaml:"not_equals,omitempty" json:"not_equals,omitempty"`
	OneOf     []any  `yaml:"one_of,omitempty" json:"one_of,omitempty"`
	AnyOf     []any  `yaml:"any_of,omitempty" json:"any_of,omitempty"`
	Prefix    string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Suffix    string `yaml:"suffix,omitempty" json:"suffix,omitempty"`
	Regex     string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Contains  any    `yaml:"contains,omitempty" json:"contains,omitempty"`
}

type Propagation struct {
	From string `yaml:"from" json:"from"`
}
type Permission struct {
	Resources []string `yaml:"resources" json:"resources"`
}
type Role struct {
	Permissions []string `yaml:"permissions" json:"permissions"`
}
type Resource struct {
	Relationships map[string]Relationship `yaml:"relationships" json:"relationships"`
	Inheritance   []Inheritance           `yaml:"inheritance,omitempty" json:"inheritance,omitempty"`
}
type Relationship struct {
	Targets     []string `yaml:"targets" json:"targets"`
	Cardinality string   `yaml:"cardinality" json:"cardinality"`
	Required    bool     `yaml:"required" json:"required"`
}
type Inheritance struct {
	Relationship string   `yaml:"relationship" json:"relationship"`
	Permissions  []string `yaml:"permissions" json:"permissions"`
}

func Parse(data []byte) (*Config, error) { return Decode(bytes.NewReader(data)) }

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configuration: %w", err)
	}
	defer f.Close()
	return Decode(f)
}

func Decode(r io.Reader) (*Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode configuration: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode configuration: multiple YAML documents are not supported")
		}
		return nil, fmt.Errorf("decode configuration: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Fingerprint() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	canonical, err := c.canonicalCopy()
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("canonicalize configuration: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (c *Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if c.Version != Version {
		add("version: must be %d", Version)
	}
	if len(c.Permissions) == 0 {
		add("permissions: at least one permission is required")
	}
	if len(c.Roles) == 0 {
		add("roles: at least one role is required")
	}
	generatedPermissions := map[string]string{}
	for name := range c.Permissions {
		generated := strings.ReplaceAll(name, ".", "_")
		if prior, exists := generatedPermissions[generated]; exists {
			add("permissions.%s: generated relation collides with permission %q", name, prior)
		}
		generatedPermissions[generated] = name
	}

	for _, name := range sortedKeys(c.Resources) {
		r := c.Resources[name]
		if !identifierRE.MatchString(name) || reservedTypes[name] {
			add("resources.%s: invalid or reserved resource type", name)
		}
		for _, relName := range sortedKeys(r.Relationships) {
			rel := r.Relationships[relName]
			if !identifierRE.MatchString(relName) || strings.HasPrefix(relName, "role_") || strings.HasPrefix(relName, "permission_") {
				add("resources.%s.relationships.%s: invalid or reserved relationship", name, relName)
			}
			if len(rel.Targets) == 0 {
				add("resources.%s.relationships.%s.targets: at least one target is required", name, relName)
			}
			seen := map[string]bool{}
			for _, target := range rel.Targets {
				if seen[target] {
					add("resources.%s.relationships.%s.targets: duplicate target %q", name, relName, target)
				}
				seen[target] = true
				if _, ok := c.Resources[target]; !ok {
					add("resources.%s.relationships.%s.targets: unknown resource type %q", name, relName, target)
				}
			}
			if rel.Cardinality != "one" && rel.Cardinality != "many" {
				add("resources.%s.relationships.%s.cardinality: must be one or many", name, relName)
			}
		}
		seenInheritance := map[string]bool{}
		for i, inheritance := range r.Inheritance {
			if _, ok := r.Relationships[inheritance.Relationship]; !ok {
				add("resources.%s.inheritance[%d].relationship: unknown relationship %q", name, i, inheritance.Relationship)
			}
			if len(inheritance.Permissions) == 0 {
				add("resources.%s.inheritance[%d].permissions: at least one permission is required", name, i)
			}
			for _, p := range inheritance.Permissions {
				key := inheritance.Relationship + "\x00" + p
				if seenInheritance[key] {
					add("resources.%s.inheritance: duplicate inheritance of %q through %q", name, p, inheritance.Relationship)
				}
				seenInheritance[key] = true
				def, ok := c.Permissions[p]
				if !ok {
					add("resources.%s.inheritance[%d].permissions: unknown permission %q", name, i, p)
				} else if !contains(def.Resources, name) {
					add("resources.%s.inheritance[%d].permissions: permission %q does not apply to this resource", name, i, p)
				}
			}
		}
	}

	for _, name := range sortedKeys(c.Permissions) {
		p := c.Permissions[name]
		if !permissionRE.MatchString(name) {
			add("permissions.%s: permission names must contain lowercase dot-separated segments", name)
		}
		if len(p.Resources) == 0 {
			add("permissions.%s.resources: at least one resource is required", name)
		}
		seen := map[string]bool{}
		for _, resource := range p.Resources {
			if seen[resource] {
				add("permissions.%s.resources: duplicate resource %q", name, resource)
			}
			seen[resource] = true
			if resource != "audience" {
				if _, ok := c.Resources[resource]; !ok {
					add("permissions.%s.resources: unknown resource type %q", name, resource)
				}
			}
		}
		used := false
		for _, role := range c.Roles {
			if contains(role.Permissions, name) {
				used = true
				break
			}
		}
		if !used {
			add("permissions.%s: permission is not granted by any role", name)
		}
	}
	for _, name := range sortedKeys(c.Roles) {
		role := c.Roles[name]
		if !identifierRE.MatchString(name) {
			add("roles.%s: invalid role identifier", name)
		}
		if len(role.Permissions) == 0 {
			add("roles.%s.permissions: at least one permission is required", name)
		}
		seen := map[string]bool{}
		for _, p := range role.Permissions {
			if seen[p] {
				add("roles.%s.permissions: duplicate permission %q", name, p)
			}
			seen[p] = true
			if _, ok := c.Permissions[p]; !ok {
				add("roles.%s.permissions: unknown permission %q", name, p)
			}
		}
	}
	prefixes := map[string]string{}
	for _, name := range sortedKeys(c.TokenSources) {
		prefix := c.TokenSources[name].Identity.Prefix
		if prior, exists := prefixes[prefix]; exists && prefix != "" {
			add("token_sources.%s.identity.prefix: duplicates token source %q", name, prior)
		}
		prefixes[prefix] = name
		validateTokenSource(name, c.TokenSources[name], add)
	}
	sort.Strings(errs)
	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration:\n- %s", strings.Join(errs, "\n- "))
	}
	return nil
}

func (c *Config) canonicalCopy() (*Config, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("canonicalize configuration: %w", err)
	}
	var out Config
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("canonicalize configuration: %w", err)
	}
	for name, source := range out.TokenSources {
		sort.Strings(source.Algorithms)
		if source.Validation.Audience != nil {
			sortMatcher(source.Validation.Audience)
		}
		for claim, matcher := range source.Validation.Claims {
			sortMatcher(&matcher)
			source.Validation.Claims[claim] = matcher
		}
		out.TokenSources[name] = source
	}
	for name, permission := range out.Permissions {
		sort.Strings(permission.Resources)
		out.Permissions[name] = permission
	}
	for name, role := range out.Roles {
		sort.Strings(role.Permissions)
		out.Roles[name] = role
	}
	for name, resource := range out.Resources {
		for relationName, relationship := range resource.Relationships {
			sort.Strings(relationship.Targets)
			resource.Relationships[relationName] = relationship
		}
		for i := range resource.Inheritance {
			sort.Strings(resource.Inheritance[i].Permissions)
		}
		sort.Slice(resource.Inheritance, func(i, j int) bool {
			a, b := resource.Inheritance[i], resource.Inheritance[j]
			if a.Relationship != b.Relationship {
				return a.Relationship < b.Relationship
			}
			return strings.Join(a.Permissions, "\x00") < strings.Join(b.Permissions, "\x00")
		})
		out.Resources[name] = resource
	}
	return &out, nil
}

func sortMatcher(m *Matcher) {
	sort.Slice(m.OneOf, func(i, j int) bool {
		a, _ := json.Marshal(m.OneOf[i])
		b, _ := json.Marshal(m.OneOf[j])
		return string(a) < string(b)
	})
	sort.Slice(m.AnyOf, func(i, j int) bool {
		a, _ := json.Marshal(m.AnyOf[i])
		b, _ := json.Marshal(m.AnyOf[j])
		return string(a) < string(b)
	})
}

func validateTokenSource(name string, s TokenSource, add func(string, ...any)) {
	path := "token_sources." + name
	if !identifierRE.MatchString(name) {
		add("%s: invalid token source identifier", path)
	}
	u, err := url.Parse(s.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		add("%s.issuer: must be an absolute HTTPS URL", path)
	}
	modes := 0
	if s.Keys.Discovery {
		modes++
	}
	if s.Keys.JWKSURL != "" {
		modes++
		u, err := url.Parse(s.Keys.JWKSURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			add("%s.keys.jwks_url: must be an absolute HTTPS URL", path)
		}
	}
	if len(s.Keys.JWKS) > 0 {
		modes++
	}
	if s.Keys.PublicKey != "" {
		modes++
	}
	if modes != 1 {
		add("%s.keys: exactly one of discovery, jwks_url, jwks, or public_key is required", path)
	}
	if len(s.Algorithms) == 0 {
		add("%s.algorithms: at least one algorithm is required", path)
	}
	seen := map[string]bool{}
	for _, alg := range s.Algorithms {
		if seen[alg] {
			add("%s.algorithms: duplicate algorithm %q", path, alg)
		}
		seen[alg] = true
		if !algorithms[alg] {
			add("%s.algorithms: unsupported algorithm %q", path, alg)
		}
	}
	if s.Identity.SubjectClaim == "" {
		add("%s.identity.subject_claim: is required", path)
	}
	if !identifierRE.MatchString(s.Identity.Prefix) {
		add("%s.identity.prefix: invalid principal prefix", path)
	}
	if s.Validation.Audience != nil {
		validateMatcher(path+".validation.audience", *s.Validation.Audience, add)
	}
	for _, claim := range sortedKeys(s.Validation.Claims) {
		if claim == "" {
			add("%s.validation.claims: claim name cannot be empty", path)
		}
		validateMatcher(path+".validation.claims."+claim, s.Validation.Claims[claim], add)
	}
	for _, output := range sortedKeys(s.PropagateClaims) {
		if reservedClaims[output] {
			add("%s.propagate_claims.%s: reserved JWT claim cannot be propagated", path, output)
		}
		if s.PropagateClaims[output].From == "" {
			add("%s.propagate_claims.%s.from: is required", path, output)
		}
	}
}

func validateMatcher(path string, m Matcher, add func(string, ...any)) {
	n := 0
	if m.Exists != nil {
		n++
	}
	if m.Equals != nil {
		n++
	}
	if m.NotEquals != nil {
		n++
	}
	if m.OneOf != nil {
		n++
		if len(m.OneOf) == 0 {
			add("%s.one_of: cannot be empty", path)
		}
	}
	if m.AnyOf != nil {
		n++
		if len(m.AnyOf) == 0 {
			add("%s.any_of: cannot be empty", path)
		}
	}
	if m.Prefix != "" {
		n++
	}
	if m.Suffix != "" {
		n++
	}
	if m.Regex != "" {
		n++
		if _, err := regexp.Compile(m.Regex); err != nil {
			add("%s.regex: invalid regular expression", path)
		}
	}
	if m.Contains != nil {
		n++
	}
	if n != 1 {
		add("%s: exactly one matcher operation is required", path)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
