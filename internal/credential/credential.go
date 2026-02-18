package credential

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	hashAlgorithm       = "pbkdf2_sha256"
	saltLength          = 16
	derivedKeyLength    = 32
	pbkdf2Iterations    = 600000
	maxPBKDF2Iterations = 10000000
)

// HashSecret creates a salted PBKDF2-SHA256 hash of a secret.
// Returns the hash in the format: pbkdf2_sha256:<iterations>:<salt_hex>:<hash_hex>
func HashSecret(secret string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash, err := pbkdf2.Key(sha256.New, secret, salt, pbkdf2Iterations, derivedKeyLength)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}

	return fmt.Sprintf("%s:%d:%s:%s",
		hashAlgorithm,
		pbkdf2Iterations,
		hex.EncodeToString(salt),
		hex.EncodeToString(hash),
	), nil
}

// VerifySecret verifies a client secret against a stored hash.
// The stored hash must be in the format: pbkdf2_sha256:<iterations>:<salt_hex>:<hash_hex>
func VerifySecret(secret, storedHash string) bool {
	// Parse the stored hash
	parts := strings.SplitN(storedHash, ":", 4)
	if len(parts) != 4 || parts[0] != hashAlgorithm {
		return false
	}

	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 || iterations > maxPBKDF2Iterations {
		return false
	}

	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	if len(salt) != saltLength {
		return false
	}

	expectedHash, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	if len(expectedHash) == 0 {
		return false
	}

	actualHash, err := pbkdf2.Key(sha256.New, secret, salt, iterations, len(expectedHash))
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}
