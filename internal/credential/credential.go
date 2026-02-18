package credential

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// HashSecret creates a salted SHA-256 hash of a client secret.
// Returns the hash in the format: sha256:<salt_hex>:<hash_hex>
func HashSecret(secret string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(secret))
	hash := h.Sum(nil)

	return fmt.Sprintf("sha256:%s:%s",
		hex.EncodeToString(salt),
		hex.EncodeToString(hash),
	), nil
}

// VerifySecret verifies a client secret against a stored hash.
// The stored hash must be in the format: sha256:<salt_hex>:<hash_hex>
func VerifySecret(secret, storedHash string) bool {
	// Parse the stored hash
	parts := strings.SplitN(storedHash, ":", 3)
	if len(parts) != 3 || parts[0] != "sha256" {
		return false
	}

	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}

	expectedHash, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}

	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(secret))
	actualHash := h.Sum(nil)

	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}
