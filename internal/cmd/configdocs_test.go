package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
)

const configDocsTestYAML = `version: 1
token_sources:
  external:
    issuer: https://issuer.example
    keys:
      jwks:
        keys:
          - kty: RSA
            kid: public-key
            n: public-modulus
            e: AQAB
            d: TOP-SECRET-JWK-MATERIAL
            private_key: ANOTHER-SECRET
            client_secret: THIRD-SECRET
    algorithms: [RS256]
    identity:
      subject_claim: sub
      prefix: external
    validation:
      audience:
        any_of: [https://auth.example]
    propagate_claims:
      email:
        from: email
permissions:
  document.read:
    resources: [document]
  management.grants.write:
    resources: [audience]
roles:
  administrator:
    permissions: [management.grants.write]
  reader:
    permissions: [document.read]
resources:
  document:
    relationships:
      parent:
        targets: [document]
        cardinality: one
        required: false
`

func TestRenderConfigDocsIsDeterministicAndBuildsNavigableGuide(t *testing.T) {
	cfg, err := config.Parse([]byte(configDocsTestYAML))
	if err != nil {
		t.Fatal(err)
	}
	first, err := renderConfigDocs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := renderConfigDocs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	expectedPages := append([]string(nil), configDocsPageOrder...)
	expectedPages = append(expectedPages,
		"permission-document.read.html",
		"permission-management.grants.write.html",
		"role-administrator.html",
		"role-reader.html",
	)
	for _, name := range expectedPages {
		if !bytes.Equal(first[name], second[name]) {
			t.Fatalf("page %s changed between identical renders", name)
		}
		body := string(first[name])
		if !strings.Contains(body, `id="site-search"`) || !strings.Contains(body, `name="viewport"`) {
			t.Fatalf("page %s does not include responsive search navigation", name)
		}
		for _, secret := range []string{"TOP-SECRET-JWK-MATERIAL", "ANOTHER-SECRET", "THIRD-SECRET"} {
			if strings.Contains(body, secret) {
				t.Fatalf("page %s contains unredacted secret %q", name, secret)
			}
		}
	}
	if _, ok := first["configuration.html"]; ok {
		t.Fatal("guide includes a raw configuration page")
	}
	permission := string(first["permission-document.read.html"])
	if !strings.Contains(permission, `href="role-reader.html"`) || !strings.Contains(permission, `href="resources.html#resource-document"`) {
		t.Fatalf("permission detail page does not connect roles and resources:\n%s", permission)
	}
	role := string(first["role-reader.html"])
	if !strings.Contains(role, `href="permission-document.read.html"`) || !strings.Contains(role, "Effective access by resource type") {
		t.Fatalf("role detail page does not explain effective access:\n%s", role)
	}
	index := string(first["index.html"])
	if !strings.Contains(index, "How access works") || !strings.Contains(index, "applications authorize permission names") {
		t.Fatalf("overview does not explain the application authorization flow:\n%s", index)
	}
	if !strings.Contains(string(first["management-permissions.html"]), "/v1/manage/grants") {
		t.Fatal("management page does not include the built-in grant routes")
	}
}

func TestConfigDocsUsesConfiguredManagementPermissionMappings(t *testing.T) {
	input := configDocsTestYAML + `
management:
  permissions:
    grants:
      write: platform.grants.write
`
	input = strings.Replace(input, "permissions:\n  document.read:", "permissions:\n  platform.grants.write:\n    resources: [audience]\n  document.read:", 1)
	input = strings.Replace(input, "permissions: [management.grants.write]", "permissions: [management.grants.write, platform.grants.write]", 1)
	cfg, err := config.Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	pages, err := renderConfigDocs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := string(pages["management-permissions.html"])
	if !strings.Contains(body, "platform.grants.write") || !strings.Contains(body, "/v1/manage/grants") {
		t.Fatalf("configured management mapping missing from output:\n%s", body)
	}
	permissionBody := string(pages["permission-platform.grants.write.html"])
	if !strings.Contains(permissionBody, "/v1/manage/grants") {
		t.Fatalf("permission detail does not explain its management usage:\n%s", permissionBody)
	}
}

func TestConfigDocsMalformedInputDoesNotCreateOutput(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "broken.yaml")
	if err := os.WriteFile(configPath, []byte("version: [not valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(directory, "generated")
	if err := ConfigDocs([]string{"--config", configPath, "--output-dir", outputDir}); err == nil {
		t.Fatal("expected malformed configuration error")
	}
	if _, err := os.Stat(outputDir); !os.IsNotExist(err) {
		t.Fatalf("malformed input created output directory: %v", err)
	}
}

func TestConfigDocsWritesAllPagesToOutputDirectory(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "serviceauth.yaml")
	if err := os.WriteFile(configPath, []byte(configDocsTestYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(directory, "site")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	obsoletePage := filepath.Join(outputDir, "configuration.html")
	if err := os.WriteFile(obsoletePage, []byte("stale raw configuration"), 0o600); err != nil {
		t.Fatal(err)
	}
	staleRolePage := filepath.Join(outputDir, "role-deleted.html")
	if err := os.WriteFile(staleRolePage, []byte("stale role"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigDocs([]string{"--config", configPath, "--output", outputDir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(obsoletePage); !os.IsNotExist(err) {
		t.Fatalf("obsolete raw configuration page remains after regeneration: %v", err)
	}
	if _, err := os.Stat(staleRolePage); !os.IsNotExist(err) {
		t.Fatalf("stale role page remains after regeneration: %v", err)
	}
	cfg, err := config.Parse([]byte(configDocsTestYAML))
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderConfigDocs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for name := range rendered {
		path := filepath.Join(outputDir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(body) == 0 || !bytes.Contains(body, []byte("<!doctype html>")) {
			t.Fatalf("%s is not a complete HTML page", name)
		}
	}
}
