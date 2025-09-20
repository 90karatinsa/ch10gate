package report

import (
	"fmt"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// ManifestHashToQR creates a QR code PNG encoding the provided manifest hash.
func ManifestHashToQR(hash string, size int) ([]byte, error) {
	normalized := sanitizeHash(hash)
	if normalized == "" {
		return nil, fmt.Errorf("manifest hash is empty")
	}
	if size <= 0 {
		size = 128
	}
	png, err := qrcode.Encode(normalized, qrcode.Medium, size)
	if err != nil {
		return nil, err
	}
	return png, nil
}

func sanitizeHash(hash string) string {
	upper := strings.ToUpper(strings.TrimSpace(hash))
	if upper == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range upper {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'F':
			b.WriteRune(r)
		}
	}
	return b.String()
}
