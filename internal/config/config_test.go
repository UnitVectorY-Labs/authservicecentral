package config

import (
	"strings"
	"testing"
)

const validYAML = `version: 1
token_sources:
  github:
    issuer: https://token.actions.githubusercontent.com
    keys:
      discovery: true
    algorithms: [RS256]
    identity:
      subject_claim: sub
      prefix: github
    validation:
      audience:
        any_of: [https://auth.example.com]
      claims:
        repository_owner:
          equals: example-org
        ref:
          prefix: refs/heads/
    propagate_claims:
      repository:
        from: repository
permissions:
  api.invoke:
    resources: [audience]
  document.read:
    resources: [document]
  document.write:
    resources: [document]
  folder.read:
    resources: [folder]
roles:
  reader:
    permissions: [api.invoke, document.read, folder.read]
  editor:
    permissions: [document.read, document.write]
resources:
  folder:
    relationships:
      parent:
        targets: [folder]
        cardinality: one
        required: false
  document:
    relationships:
      parent:
        targets: [folder]
        cardinality: one
        required: false
    inheritance:
      - relationship: parent
        permissions: [document.read]
`

func TestParseCompleteSchema(t *testing.T) {
	c, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || c.TokenSources["github"].Identity.Prefix != "github" {
		t.Fatalf("unexpected config: %#v", c)
	}
	if got := c.Resources["document"].Inheritance[0].Permissions[0]; got != "document.read" {
		t.Fatalf("inheritance permission = %q", got)
	}
}

func TestFingerprintIsIndependentOfMapAndYAMLOrdering(t *testing.T) {
	a, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(strings.Replace(validYAML,
		"  reader:\n    permissions: [api.invoke, document.read, folder.read]\n  editor:\n    permissions: [document.read, document.write]",
		"  editor:\n    permissions: [document.read, document.write]\n  reader:\n    permissions: [api.invoke, document.read, folder.read]", 1)))
	if err != nil {
		t.Fatal(err)
	}
	fa, _ := a.Fingerprint()
	fb, _ := b.Fingerprint()
	if fa != fb {
		t.Fatalf("fingerprints differ: %s != %s", fa, fb)
	}
}

func TestDecodeIsStrict(t *testing.T) {
	tests := map[string]string{
		"unknown field":      strings.Replace(validYAML, "version: 1", "version: 1\nsurprise: true", 1),
		"duplicate key":      strings.Replace(validYAML, "version: 1", "version: 1\nversion: 1", 1),
		"multiple documents": validYAML + "---\nversion: 1\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidationFailures(t *testing.T) {
	tests := map[string]struct{ old, new, want string }{
		"version":                      {"version: 1", "version: 2", "version: must be 1"},
		"unknown role permission":      {"permissions: [document.read, document.write]", "permissions: [document.read, missing.read]", "unknown permission"},
		"empty role":                   {"permissions: [document.read, document.write]", "permissions: []", "at least one permission"},
		"unknown permission resource":  {"resources: [document]\n  document.write", "resources: [missing]\n  document.write", "unknown resource type"},
		"unknown relationship target":  {"targets: [folder]", "targets: [missing]", "unknown resource type"},
		"bad cardinality":              {"cardinality: one", "cardinality: some", "must be one or many"},
		"bad inheritance relationship": {"relationship: parent", "relationship: owner", "unknown relationship"},
		"inapplicable inheritance":     {"permissions: [document.read]", "permissions: [folder.read]", "does not apply to this resource"},
		"reserved resource":            {"  folder:\n    relationships:", "  group:\n    relationships:", "invalid or reserved resource type"},
		"unsafe algorithm":             {"algorithms: [RS256]", "algorithms: [none]", "unsupported algorithm"},
		"two key modes":                {"discovery: true", "discovery: true\n      jwks_url: https://example.com/keys", "exactly one"},
		"bad issuer":                   {"issuer: https://token.actions.githubusercontent.com", "issuer: http://token.actions.githubusercontent.com", "absolute HTTPS"},
		"multiple matcher ops":         {"equals: example-org", "equals: example-org\n          suffix: org", "exactly one matcher"},
		"bad regex":                    {"prefix: refs/heads/", "regex: '[broken'", "invalid regular expression"},
		"reserved propagation":         {"repository:\n        from: repository", "sub:\n        from: repository", "reserved JWT claim"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			input := strings.Replace(validYAML, tc.old, tc.new, 1)
			_, err := Parse([]byte(input))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestKeyModes(t *testing.T) {
	for name, replacement := range map[string]string{
		"jwks url":    "jwks_url: https://issuer.example/keys",
		"inline jwks": "jwks:\n        keys: []",
		"public key":  "public_key: |\n        -----BEGIN PUBLIC KEY-----\n        abc\n        -----END PUBLIC KEY-----",
	} {
		t.Run(name, func(t *testing.T) {
			input := strings.Replace(validYAML, "discovery: true", replacement, 1)
			if _, err := Parse([]byte(input)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
