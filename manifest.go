package manifest

import (
	"encoding/json"
	"os"
	"time"

	"example.com/ch10gate/internal/common"
)

type Item struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Sha256 string `json:"sha256"`
	Type string `json:"type"`
}

type Manifest struct {
	CreatedAt time.Time `json:"createdAt"`
	ShaAlgo string `json:"shaAlgo"`
	Items []Item `json:"items"`
	Signature *Signature `json:"signature,omitempty"`
}

type Signature struct {
	Type string `json:"type"`
	CertSubject string `json:"certSubject,omitempty"`
	Issuer string `json:"issuer,omitempty"`
	SignatureFile string `json:"signatureFile,omitempty"`
}

func Build(paths []string) (Manifest, error) {
	m := Manifest{CreatedAt: time.Now().UTC(), ShaAlgo: "sha256"}
	for _, p := range paths {
		hex, sz, err := common.Sha256OfFile(p)
		if err != nil { return m, err }
		typ := "other"
		switch {
		case hasExt(p, ".ch10", ".tf10", ".df10"):
			typ = "ch10"
		case hasExt(p, ".tmats", ".tmt", ".txt"):
			typ = "tmats"
		case hasExt(p, ".json"):
			typ = "json"
		case hasExt(p, ".pdf"):
			typ = "pdf"
		}
		m.Items = append(m.Items, Item{Path: p, Size: sz, Sha256: hex, Type: typ})
	}
	return m, nil
}

func hasExt(path string, exts ...string) bool {
	for _, e := range exts {
		if len(path) >= len(e) && path[len(path)-len(e):] == e {
			return true
		}
	}
	return false
}

func Save(m Manifest, out string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil { return err }
	return os.WriteFile(out, b, 0644)
}
