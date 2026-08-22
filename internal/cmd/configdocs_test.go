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

func TestRenderConfigDocsIsDeterministicAndRedactsSecrets(t *testing.T) {
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
	for _, name := range configDocsPageOrder {
		if !bytes.Equal(first[name], second[name]) {
			t.Fatalf("page %s changed between identical renders", name)
		}
		body := string(first[name])
		if !strings.Contains(body, `hx-boost="true"`) {
			t.Fatalf("page %s has no HTMX navigation", name)
		}
		for _, secret := range []string{"TOP-SECRET-JWK-MATERIAL", "ANOTHER-SECRET", "THIRD-SECRET"} {
			if strings.Contains(body, secret) {
				t.Fatalf("page %s contains unredacted secret %q", name, secret)
			}
		}
	}
	configuration := string(first["configuration.html"])
	if !strings.Contains(configuration, "[REDACTED]") {
		t.Fatal("safe configuration does not show redaction marker")
	}
	if strings.Contains(configuration, "public-modulus") {
		t.Fatal("safe configuration leaked public JWK key material")
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
	if err := ConfigDocs([]string{"--config", configPath, "--output", outputDir}); err != nil {
		t.Fatal(err)
	}
	for _, name := range configDocsPageOrder {
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
