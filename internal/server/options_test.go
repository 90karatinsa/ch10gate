package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProfileManifestResolvesPaths(t *testing.T) {
	root := t.TempDir()
	manifestDir := filepath.Join(root, "profiles")
	if err := os.MkdirAll(manifestDir, 0o755); err != nil {
		t.Fatalf("MkdirAll manifest: %v", err)
	}
	type entry struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Rules     string `json:"rules"`
		Signature string `json:"signature"`
	}
	manifest := struct {
		Profiles []entry `json:"profiles"`
	}{}
	for _, id := range RequiredProfiles {
		profDir := filepath.Join(manifestDir, id)
		if err := os.MkdirAll(profDir, 0o755); err != nil {
			t.Fatalf("MkdirAll profile %s: %v", id, err)
		}
		rulesPath := filepath.Join(profDir, "rules.json")
		if err := os.WriteFile(rulesPath, []byte("{}"), 0o644); err != nil {
			t.Fatalf("WriteFile rules %s: %v", id, err)
		}
		sigPath := filepath.Join(profDir, "rules.json.sha256")
		if err := os.WriteFile(sigPath, []byte("deadbeef\n"), 0o644); err != nil {
			t.Fatalf("WriteFile signature %s: %v", id, err)
		}
		manifest.Profiles = append(manifest.Profiles, entry{
			ID:        id,
			Name:      "Profile " + id,
			Rules:     filepath.Join(id, "rules.json"),
			Signature: filepath.Join(id, "rules.json.sha256"),
		})
	}
	manifestPath := filepath.Join(manifestDir, "index.json")
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}
	packs, err := LoadProfileManifest(manifestPath)
	if err != nil {
		t.Fatalf("LoadProfileManifest: %v", err)
	}
	if len(packs) != len(RequiredProfiles) {
		t.Fatalf("expected %d packs, got %d", len(RequiredProfiles), len(packs))
	}
	for _, pack := range packs {
		if !strings.HasPrefix(pack.Rules, manifestDir) {
			t.Errorf("rules path %s not rooted under manifest dir", pack.Rules)
		}
		if _, err := os.Stat(pack.Rules); err != nil {
			t.Errorf("rules stat %s: %v", pack.Rules, err)
		}
		if pack.Signature != "" {
			if _, err := os.Stat(pack.Signature); err != nil {
				t.Errorf("signature stat %s: %v", pack.Signature, err)
			}
		}
	}
}

func TestBuildProfilePackMapMissingProfile(t *testing.T) {
	dir := t.TempDir()
	packs := make([]ProfilePack, 0, len(RequiredProfiles)-1)
	for i, id := range RequiredProfiles {
		if i == len(RequiredProfiles)-1 {
			break
		}
		rulesPath := filepath.Join(dir, id+".json")
		if err := os.WriteFile(rulesPath, []byte("{}"), 0o644); err != nil {
			t.Fatalf("WriteFile rules %s: %v", id, err)
		}
		packs = append(packs, ProfilePack{ID: id, Rules: rulesPath})
	}
	_, _, err := buildProfilePackMap(Options{ProfilePacks: packs})
	if err == nil || !strings.Contains(err.Error(), RequiredProfiles[len(RequiredProfiles)-1]) {
		t.Fatalf("expected missing profile error, got %v", err)
	}
}

func TestHandleProfilesListsConfigured(t *testing.T) {
	dir := t.TempDir()
	storage := filepath.Join(dir, "storage")
	packs := make([]ProfilePack, 0, len(RequiredProfiles))
	for _, id := range RequiredProfiles {
		rulesPath := filepath.Join(dir, id+".json")
		if err := os.WriteFile(rulesPath, []byte("{}"), 0o644); err != nil {
			t.Fatalf("WriteFile rules %s: %v", id, err)
		}
		packs = append(packs, ProfilePack{ID: id, Rules: rulesPath})
	}
	srv, err := NewServer(Options{StorageDir: storage, ProfilePacks: packs})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/profiles", nil)
	srv.handleProfiles(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	var got []string
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("Decode response: %v", err)
	}
	if len(got) != len(RequiredProfiles) {
		t.Fatalf("expected %d profiles, got %d", len(RequiredProfiles), len(got))
	}
	for i, id := range RequiredProfiles {
		if got[i] != id {
			t.Fatalf("profile mismatch at %d: want %s got %s", i, id, got[i])
		}
	}
}
