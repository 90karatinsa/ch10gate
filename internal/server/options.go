package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"example.com/ch10gate/internal/update"
)

// RequiredProfiles lists the IRIG Chapter 10 profiles that must be available
// to start the daemon.
var RequiredProfiles = []string{"106-09", "106-11", "106-13", "106-15", "106-20"}

// ProfilePack describes a rule bundle bound to a Chapter 10 profile.
type ProfilePack struct {
	ID        string `json:"id" yaml:"id"`
	Name      string `json:"name,omitempty" yaml:"name,omitempty"`
	Rules     string `json:"rules" yaml:"rules"`
	Signature string `json:"signature,omitempty" yaml:"signature,omitempty"`
}

// ManifestSigningOptions configures detached JWS manifest signing.
type ManifestSigningOptions struct {
	PrivateKeyPath  string
	CertificatePath string
}

// Options configures server creation.
type Options struct {
	StorageDir      string
	ProfileManifest string
	ProfilePacks    []ProfilePack
	ManifestSigning ManifestSigningOptions
	Concurrency     int
	EnableAdmin     bool
	UpdateInstaller *update.Installer
}

type profilePackEntry struct {
	id            string
	name          string
	rulesPath     string
	signaturePath string
}

// LoadProfileManifest parses a manifest JSON document that enumerates the
// available rule packs. Relative paths are resolved against the manifest's
// directory.
func LoadProfileManifest(path string) ([]ProfilePack, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("manifest path is empty")
	}
	manifestPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("manifest path: %w", err)
	}
	f, err := os.Open(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("open manifest: %w", err)
	}
	defer f.Close()
	var doc struct {
		Profiles []ProfilePack `json:"profiles"`
	}
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if len(doc.Profiles) == 0 {
		return nil, errors.New("manifest contains no profiles")
	}
	base := filepath.Dir(manifestPath)
	out := make([]ProfilePack, len(doc.Profiles))
	for i, pack := range doc.Profiles {
		resolved, err := resolveProfilePaths(base, pack)
		if err != nil {
			return nil, err
		}
		out[i] = resolved
	}
	return out, nil
}

func resolveProfilePaths(base string, pack ProfilePack) (ProfilePack, error) {
	pack.ID = strings.TrimSpace(pack.ID)
	pack.Name = strings.TrimSpace(pack.Name)
	pack.Rules = strings.TrimSpace(pack.Rules)
	pack.Signature = strings.TrimSpace(pack.Signature)
	if pack.ID == "" {
		return ProfilePack{}, errors.New("manifest profile entry missing id")
	}
	if pack.Rules == "" {
		return ProfilePack{}, fmt.Errorf("manifest profile %s missing rules path", pack.ID)
	}
	if !filepath.IsAbs(pack.Rules) {
		pack.Rules = filepath.Join(base, pack.Rules)
	}
	if pack.Signature != "" && !filepath.IsAbs(pack.Signature) {
		pack.Signature = filepath.Join(base, pack.Signature)
	}
	return pack, nil
}

func buildProfilePackMap(opts Options) (map[string]profilePackEntry, []string, error) {
	packs := opts.ProfilePacks
	if len(packs) == 0 {
		manifest := opts.ProfileManifest
		if strings.TrimSpace(manifest) == "" {
			manifest = filepath.Join("profiles", "index.json")
		}
		var err error
		packs, err = LoadProfileManifest(manifest)
		if err != nil {
			return nil, nil, fmt.Errorf("load profile manifest: %w", err)
		}
	}
	entries := make(map[string]profilePackEntry)
	for _, pack := range packs {
		id := strings.TrimSpace(pack.ID)
		rulesPath := strings.TrimSpace(pack.Rules)
		if id == "" {
			return nil, nil, errors.New("profile pack missing id")
		}
		if rulesPath == "" {
			return nil, nil, fmt.Errorf("profile %s missing rules path", id)
		}
		if !filepath.IsAbs(rulesPath) {
			abs, err := filepath.Abs(rulesPath)
			if err != nil {
				return nil, nil, fmt.Errorf("profile %s rules abs: %w", id, err)
			}
			rulesPath = abs
		}
		if _, err := os.Stat(rulesPath); err != nil {
			return nil, nil, fmt.Errorf("profile %s rules: %w", id, err)
		}
		signaturePath := strings.TrimSpace(pack.Signature)
		if signaturePath != "" {
			if !filepath.IsAbs(signaturePath) {
				abs, err := filepath.Abs(signaturePath)
				if err != nil {
					return nil, nil, fmt.Errorf("profile %s signature abs: %w", id, err)
				}
				signaturePath = abs
			}
			if _, err := os.Stat(signaturePath); err != nil {
				return nil, nil, fmt.Errorf("profile %s signature: %w", id, err)
			}
		}
		if _, exists := entries[id]; exists {
			return nil, nil, fmt.Errorf("duplicate profile %s configured", id)
		}
		entries[id] = profilePackEntry{
			id:            id,
			name:          pack.Name,
			rulesPath:     rulesPath,
			signaturePath: signaturePath,
		}
	}
	for _, required := range RequiredProfiles {
		if _, ok := entries[required]; !ok {
			return nil, nil, fmt.Errorf("required profile %s not configured", required)
		}
	}
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return entries, ids, nil
}
