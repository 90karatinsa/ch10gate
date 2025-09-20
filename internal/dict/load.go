package dict

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"example.com/ch10gate/internal/tmats"
)

func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file JSONFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	return FromJSON(file)
}

func EnsureLoaded(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("empty dictionary path")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("dictionary path %s is a directory", path)
	}
	return Load(path)
}

func PathFromTMATS(doc *tmats.Document) (string, bool) {
	if doc == nil {
		return "", false
	}
	candidates := []string{"G\\DICT", "G\\ICD", "G\\IDT"}
	for _, key := range candidates {
		if val, ok := doc.Get(key); ok {
			trimmed := strings.TrimSpace(val)
			if trimmed != "" {
				return trimmed, true
			}
		}
	}
	for _, comment := range doc.Comments() {
		trimmed := strings.TrimSpace(comment)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			trimmed = strings.TrimSpace(trimmed[1:])
		}
		lower := strings.ToLower(trimmed)
		prefixes := []string{"dictionary", "dict", "icd"}
		for _, prefix := range prefixes {
			for _, sep := range []string{":", "="} {
				token := prefix + sep
				if strings.HasPrefix(lower, token) {
					value := strings.TrimSpace(trimmed[len(token):])
					value = strings.Trim(value, "\"'")
					if value != "" {
						return value, true
					}
				}
			}
		}
	}
	return "", false
}

func ResolveTMATSPath(tmatsPath, dictPath string) string {
	if dictPath == "" {
		return ""
	}
	if filepath.IsAbs(dictPath) {
		return dictPath
	}
	base := filepath.Dir(tmatsPath)
	if base == "" {
		return dictPath
	}
	return filepath.Join(base, dictPath)
}
