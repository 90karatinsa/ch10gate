package server

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.com/ch10gate/internal/rules"
)

func TestHandleAutoFixDryRun(t *testing.T) {
	tmp := t.TempDir()
	storage := filepath.Join(tmp, "storage")
	if err := os.Mkdir(storage, 0o755); err != nil {
		t.Fatalf("mkdir storage: %v", err)
	}
	packs := make([]ProfilePack, 0, len(RequiredProfiles))
	for _, id := range RequiredProfiles {
		rulesPath := filepath.Join(tmp, id+".json")
		payload := []byte(`{"rulePackId":"` + id + `","profile":"` + id + `","version":"1.0","rules":[]}`)
		if err := os.WriteFile(rulesPath, payload, 0o644); err != nil {
			t.Fatalf("write rules %s: %v", id, err)
		}
		packs = append(packs, ProfilePack{ID: id, Rules: rulesPath})
	}
	srv, err := NewServer(Options{StorageDir: storage, ProfilePacks: packs})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	router, err := NewRouter(srv)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	ts := httptest.NewServer(router)
	defer ts.Close()

	inputPath := filepath.Join(tmp, "input.ch10")
	writeBadChecksumChapter10(t, inputPath)

	override := rules.RulePack{
		RulePackId: "dry-run-test",
		Version:    "1.0",
		Profile:    "106-15",
		Rules: []rules.Rule{{
			RuleId:   "RP-0002",
			Scope:    "file",
			Severity: rules.ERROR,
			Fixable:  true,
			FixFunc:  "FixHeaderChecksum",
			Message:  "fix header",
		}},
	}

	reqBody := struct {
		Input    string         `json:"input"`
		Profile  string         `json:"profile"`
		DryRun   bool           `json:"dryRun"`
		RulePack rules.RulePack `json:"rulePack"`
	}{
		Input:    inputPath,
		Profile:  "106-15",
		DryRun:   true,
		RulePack: override,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := http.Post(ts.URL+"/auto-fix", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /auto-fix: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/auto-fix status %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Diagnostics []rules.Diagnostic `json:"diagnostics"`
		Outputs     []ArtifactRef      `json:"outputs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out.Outputs) != 0 {
		t.Fatalf("expected no outputs during dry-run, got %d", len(out.Outputs))
	}
	if len(out.Diagnostics) == 0 {
		t.Fatalf("expected diagnostics in response")
	}
	diag := out.Diagnostics[0]
	if !diag.FixSuggested {
		t.Fatalf("expected fix suggested in diagnostic: %+v", diag)
	}
	if diag.FixApplied {
		t.Fatalf("expected fixApplied false during dry-run: %+v", diag)
	}
	if diag.FixPatchId != "" {
		t.Fatalf("expected no fix patch id during dry-run: %+v", diag)
	}
	if diag.Message == "" || !strings.Contains(diag.Message, "would fix") {
		t.Fatalf("unexpected diagnostic message: %+v", diag)
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	if binary.BigEndian.Uint16(data[16:18]) != 0xFFFF {
		t.Fatalf("header checksum should remain unchanged during dry-run")
	}
}

func writeBadChecksumChapter10(t *testing.T, path string) {
	t.Helper()
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	total := 20 + len(payload)
	buf := make([]byte, total)
	binary.BigEndian.PutUint16(buf[0:2], 0xEB25)
	binary.BigEndian.PutUint16(buf[2:4], 1)
	binary.BigEndian.PutUint32(buf[4:8], uint32(total-4))
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(payload)))
	binary.BigEndian.PutUint16(buf[12:14], 0x08)
	// sequence and flags zero
	buf[14] = 0
	buf[15] = 0
	binary.BigEndian.PutUint16(buf[16:18], 0xFFFF)
	copy(buf[20:], payload)
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
