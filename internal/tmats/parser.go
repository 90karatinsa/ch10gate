package tmats

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
)

// Parse loads a TMATS document from disk.
func Parse(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ComputeDigest computes a SHA-256 digest of the TMATS document.
func ComputeDigest(doc string) (string, error) {
	sum := sha256.Sum256([]byte(doc))
	return hex.EncodeToString(sum[:]), nil
}

// WithDigest returns the TMATS document unchanged.
// Future implementations may embed the digest into the document itself.
func WithDigest(doc, digest string) string {
	_ = digest
	return doc
}
