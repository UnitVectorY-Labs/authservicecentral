package credential

import (
	"strings"
	"testing"
)

func TestHashSecretFormat(t *testing.T) {
	hash, err := HashSecret("my-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parts := strings.SplitN(hash, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d in %q", len(parts), hash)
	}
	if parts[0] != "sha256" {
		t.Errorf("prefix = %q, want sha256", parts[0])
	}
	// salt should be 32 hex chars (16 bytes)
	if len(parts[1]) != 32 {
		t.Errorf("salt hex length = %d, want 32", len(parts[1]))
	}
	// hash should be 64 hex chars (32 bytes)
	if len(parts[2]) != 64 {
		t.Errorf("hash hex length = %d, want 64", len(parts[2]))
	}
}

func TestVerifySecretCorrect(t *testing.T) {
	secret := "my-client-secret"
	hash, err := HashSecret(secret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if !VerifySecret(secret, hash) {
		t.Error("VerifySecret should return true for correct secret")
	}
}

func TestVerifySecretWrong(t *testing.T) {
	hash, err := HashSecret("correct-secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if VerifySecret("wrong-secret", hash) {
		t.Error("VerifySecret should return false for wrong secret")
	}
}

func TestVerifySecretInvalidFormat(t *testing.T) {
	if VerifySecret("secret", "not-a-valid-hash") {
		t.Error("VerifySecret should return false for invalid format")
	}
}

func TestVerifySecretEmptyString(t *testing.T) {
	if VerifySecret("secret", "") {
		t.Error("VerifySecret should return false for empty hash")
	}
}

func TestHashSecretUniqueSalts(t *testing.T) {
	hash1, err := HashSecret("same-secret")
	if err != nil {
		t.Fatalf("hash1: %v", err)
	}
	hash2, err := HashSecret("same-secret")
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}

	if hash1 == hash2 {
		t.Error("two hashes of the same secret should differ (different salts)")
	}

	// But both should verify
	if !VerifySecret("same-secret", hash1) {
		t.Error("hash1 should verify")
	}
	if !VerifySecret("same-secret", hash2) {
		t.Error("hash2 should verify")
	}
}
