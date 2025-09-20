package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"example.com/ch10gate/internal/manifest"
	"example.com/ch10gate/internal/report"
	"example.com/ch10gate/internal/rules"
)

// Server coordinates HTTP handlers and manages temporary artifacts produced by
// validation requests.
type Server struct {
	artifacts   *ArtifactStore
	workDir     string
	uploadsDir  string
	profilePack map[string]string
	concurrency int
}

// Options configures server creation.
type Options struct {
	StorageDir   string
	ProfilePacks map[string]string
	Concurrency  int
}

// Artifact represents a file generated or stored by the daemon.
type Artifact struct {
	ID          string
	Path        string
	Name        string
	ContentType string
	Size        int64
	Kind        string
}

// ArtifactRef is the public representation returned in API responses.
type ArtifactRef struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ContentType string `json:"contentType,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Kind        string `json:"kind,omitempty"`
}

// ArtifactStore keeps track of generated artifacts for later download.
type ArtifactStore struct {
	mu      sync.RWMutex
	entries map[string]Artifact
}

// NewServer constructs a Server rooted at a temporary workspace directory.
func NewServer(opts Options) (*Server, error) {
	storageDir := opts.StorageDir
	if storageDir == "" {
		storageDir = os.TempDir()
	}
	if err := os.MkdirAll(storageDir, 0o755); err != nil {
		return nil, err
	}
	workDir, err := os.MkdirTemp(storageDir, "ch10d-")
	if err != nil {
		return nil, err
	}
	uploadsDir := filepath.Join(workDir, "uploads")
	if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
		os.RemoveAll(workDir)
		return nil, err
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}
	profilePack := map[string]string{
		"106-15": filepath.Join("profiles", "106-15", "rules-min.json"),
	}
	for profile, pack := range opts.ProfilePacks {
		if strings.TrimSpace(profile) == "" || strings.TrimSpace(pack) == "" {
			continue
		}
		profilePack[profile] = pack
	}
	s := &Server{
		artifacts:   &ArtifactStore{entries: make(map[string]Artifact)},
		workDir:     workDir,
		uploadsDir:  uploadsDir,
		profilePack: profilePack,
		concurrency: concurrency,
	}
	return s, nil
}

// Close removes any temporary state associated with the server.
func (s *Server) Close() error {
	if s == nil || s.workDir == "" {
		return nil
	}
	return os.RemoveAll(s.workDir)
}

func (s *Server) tempPath(pattern string) (string, error) {
	f, err := os.CreateTemp(s.workDir, pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	f.Close()
	return name, nil
}

func (s *Server) addArtifact(path, displayName, contentType, kind string) (Artifact, error) {
	if path == "" {
		return Artifact{}, errors.New("empty path")
	}
	info, err := os.Stat(path)
	if err != nil {
		return Artifact{}, err
	}
	id := randomID()
	art := Artifact{
		ID:          id,
		Path:        path,
		Name:        displayName,
		ContentType: contentType,
		Size:        info.Size(),
		Kind:        kind,
	}
	if art.Name == "" {
		art.Name = filepath.Base(path)
	}
	if art.ContentType == "" {
		art.ContentType = guessContentType(art.Name)
	}
	s.artifacts.mu.Lock()
	s.artifacts.entries[id] = art
	s.artifacts.mu.Unlock()
	return art, nil
}

func (s *Server) getArtifact(id string) (Artifact, bool) {
	s.artifacts.mu.RLock()
	art, ok := s.artifacts.entries[id]
	s.artifacts.mu.RUnlock()
	return art, ok
}

func (s *Server) resolvePath(token string) (string, error) {
	if token == "" {
		return "", errors.New("empty input path")
	}
	if art, ok := s.getArtifact(token); ok {
		return art.Path, nil
	}
	abs := token
	if !filepath.IsAbs(token) {
		abs = filepath.Clean(token)
	}
	if _, err := os.Stat(abs); err != nil {
		return "", err
	}
	return abs, nil
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stream := r.URL.Query().Get("stream") == "true"
	var req struct {
		Inputs            []string        `json:"inputs"`
		TMATS             string          `json:"tmats"`
		Profile           string          `json:"profile"`
		RulePack          *rules.RulePack `json:"rulePack"`
		IncludeTimestamps *bool           `json:"includeTimestamps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
		return
	}
	if len(req.Inputs) == 0 {
		http.Error(w, "inputs required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Profile) == "" {
		http.Error(w, "profile required", http.StatusBadRequest)
		return
	}
	inputPath, err := s.resolvePath(req.Inputs[0])
	if err != nil {
		http.Error(w, fmt.Sprintf("input resolve: %v", err), http.StatusBadRequest)
		return
	}
	var tmatsPath string
	if req.TMATS != "" {
		if tmatsPath, err = s.resolvePath(req.TMATS); err != nil {
			http.Error(w, fmt.Sprintf("tmats resolve: %v", err), http.StatusBadRequest)
			return
		}
	}
	rp, err := s.loadRulePack(req.Profile, req.RulePack)
	if err != nil {
		http.Error(w, fmt.Sprintf("load rulepack: %v", err), http.StatusBadRequest)
		return
	}
	engine := rules.NewEngine(rp)
	engine.RegisterBuiltins()
	engine.SetConcurrency(s.concurrency)
	includeTimestamps := true
	if req.IncludeTimestamps != nil {
		includeTimestamps = *req.IncludeTimestamps
	}
	engine.SetConfigValue("diag.include_timestamps", includeTimestamps)
	ctx := &rules.Context{InputFile: inputPath, TMATSFile: tmatsPath, Profile: req.Profile}

	if stream {
		writer := NewNDJSONWriter(w)
		engine.SetDiagnosticCallback(func(d rules.Diagnostic) error {
			return writer.WriteDiagnostic(d)
		})
		w.Header().Set("Content-Type", "application/x-ndjson")
		diags, err := engine.Eval(ctx)
		engine.SetDiagnosticCallback(nil)
		if err != nil {
			_ = writer.WriteObject(map[string]any{
				"type":  "error",
				"error": err.Error(),
			})
			return
		}
		rep := engine.MakeAcceptance()
		diagPath, err := s.tempPath("diagnostics-*.ndjson")
		if err != nil {
			_ = writer.WriteObject(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		if err := engine.WriteDiagnosticsNDJSON(diagPath); err != nil {
			_ = writer.WriteObject(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		accPath, err := s.tempPath("acceptance-*.json")
		if err != nil {
			_ = writer.WriteObject(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		if err := report.SaveAcceptanceJSON(rep, accPath); err != nil {
			_ = writer.WriteObject(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		pdfPath, err := s.tempPath("acceptance-*.pdf")
		if err != nil {
			_ = writer.WriteObject(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		if err := report.SaveAcceptancePDF(rep, pdfPath, report.PDFOptions{}); err != nil {
			_ = writer.WriteObject(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		diagArt, err := s.addArtifact(diagPath, "diagnostics.ndjson", "application/x-ndjson", "diagnostics")
		if err != nil {
			_ = writer.WriteObject(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		accArt, err := s.addArtifact(accPath, "acceptance_report.json", "application/json", "acceptance")
		if err != nil {
			_ = writer.WriteObject(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		pdfArt, err := s.addArtifact(pdfPath, "acceptance_report.pdf", "application/pdf", "acceptance")
		if err != nil {
			_ = writer.WriteObject(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		summary := struct {
			Type       string        `json:"type"`
			Acceptance any           `json:"acceptance"`
			Artifacts  []ArtifactRef `json:"artifacts"`
			Total      int           `json:"diagnostics"`
		}{
			Type:       "acceptance",
			Acceptance: rep,
			Artifacts: []ArtifactRef{
				toRef(diagArt),
				toRef(accArt),
				toRef(pdfArt),
			},
			Total: len(diags),
		}
		_ = writer.WriteObject(summary)
		return
	}

	diags, err := engine.Eval(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("eval: %v", err), http.StatusInternalServerError)
		return
	}
	diagPath, err := s.tempPath("diagnostics-*.ndjson")
	if err != nil {
		http.Error(w, fmt.Sprintf("diagnostics temp: %v", err), http.StatusInternalServerError)
		return
	}
	if err := engine.WriteDiagnosticsNDJSON(diagPath); err != nil {
		http.Error(w, fmt.Sprintf("write diagnostics: %v", err), http.StatusInternalServerError)
		return
	}
	rep := engine.MakeAcceptance()
	accPath, err := s.tempPath("acceptance-*.json")
	if err != nil {
		http.Error(w, fmt.Sprintf("acceptance temp: %v", err), http.StatusInternalServerError)
		return
	}
	if err := report.SaveAcceptanceJSON(rep, accPath); err != nil {
		http.Error(w, fmt.Sprintf("write acceptance: %v", err), http.StatusInternalServerError)
		return
	}
	pdfPath, err := s.tempPath("acceptance-*.pdf")
	if err != nil {
		http.Error(w, fmt.Sprintf("acceptance pdf temp: %v", err), http.StatusInternalServerError)
		return
	}
	if err := report.SaveAcceptancePDF(rep, pdfPath, report.PDFOptions{}); err != nil {
		http.Error(w, fmt.Sprintf("write acceptance: %v", err), http.StatusInternalServerError)
		return
	}
	diagArt, err := s.addArtifact(diagPath, "diagnostics.ndjson", "application/x-ndjson", "diagnostics")
	if err != nil {
		http.Error(w, fmt.Sprintf("register diagnostics: %v", err), http.StatusInternalServerError)
		return
	}
	accArt, err := s.addArtifact(accPath, "acceptance_report.json", "application/json", "acceptance")
	if err != nil {
		http.Error(w, fmt.Sprintf("register acceptance: %v", err), http.StatusInternalServerError)
		return
	}
	pdfArt, err := s.addArtifact(pdfPath, "acceptance_report.pdf", "application/pdf", "acceptance")
	if err != nil {
		http.Error(w, fmt.Sprintf("register acceptance: %v", err), http.StatusInternalServerError)
		return
	}
	resp := struct {
		Acceptance  rules.AcceptanceReport `json:"acceptance"`
		Diagnostics int                    `json:"diagnostics"`
		Artifacts   []ArtifactRef          `json:"artifacts"`
	}{
		Acceptance:  rep,
		Diagnostics: len(diags),
		Artifacts: []ArtifactRef{
			toRef(diagArt),
			toRef(accArt),
			toRef(pdfArt),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAutoFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Input    string          `json:"input"`
		TMATS    string          `json:"tmats"`
		Profile  string          `json:"profile"`
		RulePack *rules.RulePack `json:"rulePack"`
		DryRun   bool            `json:"dryRun"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
		return
	}
	if req.Input == "" {
		http.Error(w, "input required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Profile) == "" {
		http.Error(w, "profile required", http.StatusBadRequest)
		return
	}
	inputPath, err := s.resolvePath(req.Input)
	if err != nil {
		http.Error(w, fmt.Sprintf("input resolve: %v", err), http.StatusBadRequest)
		return
	}
	var tmatsPath string
	if req.TMATS != "" {
		if tmatsPath, err = s.resolvePath(req.TMATS); err != nil {
			http.Error(w, fmt.Sprintf("tmats resolve: %v", err), http.StatusBadRequest)
			return
		}
	}
	rp, err := s.loadRulePack(req.Profile, req.RulePack)
	if err != nil {
		http.Error(w, fmt.Sprintf("load rulepack: %v", err), http.StatusBadRequest)
		return
	}
	engine := rules.NewEngine(rp)
	engine.RegisterBuiltins()
	engine.SetConcurrency(1)
	ctx := &rules.Context{InputFile: inputPath, TMATSFile: tmatsPath, Profile: req.Profile}
	diags, err := engine.Eval(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("eval: %v", err), http.StatusInternalServerError)
		return
	}
	seen := make(map[string]struct{})
	var outputs []ArtifactRef
	for _, d := range diags {
		if !d.FixApplied || d.FixPatchId == "" {
			continue
		}
		dir := filepath.Dir(d.File)
		if dir == "" {
			dir = filepath.Dir(inputPath)
		}
		candidate := filepath.Join(dir, d.FixPatchId)
		if _, ok := seen[candidate]; ok {
			continue
		}
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		art, err := s.addArtifact(candidate, d.FixPatchId, "", "autofix")
		if err != nil {
			continue
		}
		seen[candidate] = struct{}{}
		outputs = append(outputs, toRef(art))
	}
	resp := struct {
		Diagnostics []rules.Diagnostic `json:"diagnostics"`
		Outputs     []ArtifactRef      `json:"outputs"`
	}{
		Diagnostics: diags,
		Outputs:     outputs,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Inputs  []string `json:"inputs"`
		ShaAlgo string   `json:"shaAlgo"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
		return
	}
	if len(req.Inputs) == 0 {
		http.Error(w, "inputs required", http.StatusBadRequest)
		return
	}
	if req.ShaAlgo == "" {
		req.ShaAlgo = "sha256"
	}
	if req.ShaAlgo != "" && !strings.EqualFold(req.ShaAlgo, "sha256") {
		http.Error(w, "only sha256 supported", http.StatusBadRequest)
		return
	}
	var paths []string
	for _, in := range req.Inputs {
		resolved, err := s.resolvePath(in)
		if err != nil {
			http.Error(w, fmt.Sprintf("resolve %s: %v", in, err), http.StatusBadRequest)
			return
		}
		paths = append(paths, resolved)
	}
	m, err := manifest.Build(paths)
	if err != nil {
		http.Error(w, fmt.Sprintf("build manifest: %v", err), http.StatusInternalServerError)
		return
	}
	outPath, err := s.tempPath("manifest-*.json")
	if err != nil {
		http.Error(w, fmt.Sprintf("manifest temp: %v", err), http.StatusInternalServerError)
		return
	}
	if err := manifest.Save(m, outPath); err != nil {
		http.Error(w, fmt.Sprintf("write manifest: %v", err), http.StatusInternalServerError)
		return
	}
	art, err := s.addArtifact(outPath, "manifest.json", "application/json", "manifest")
	if err != nil {
		http.Error(w, fmt.Sprintf("register manifest: %v", err), http.StatusInternalServerError)
		return
	}
	resp := struct {
		Manifest manifest.Manifest `json:"manifest"`
		Artifact ArtifactRef       `json:"artifact"`
	}{
		Manifest: m,
		Artifact: toRef(art),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	profiles := []string{"106-09", "106-11", "106-13", "106-15", "106-20"}
	writeJSON(w, http.StatusOK, profiles)
}

func (s *Server) handleArtifactDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/artifacts/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	art, ok := s.getArtifact(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(art.Path)
	if err != nil {
		http.Error(w, fmt.Sprintf("open artifact: %v", err), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.Error(w, fmt.Sprintf("stat artifact: %v", err), http.StatusInternalServerError)
		return
	}
	if art.ContentType != "" {
		w.Header().Set("Content-Type", art.ContentType)
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	disposition := fmt.Sprintf("attachment; filename=\"%s\"", art.Name)
	w.Header().Set("Content-Disposition", disposition)
	io.Copy(w, f)
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := filepath.Join("api", "openapi.yaml")
	http.ServeFile(w, r, path)
}

func (s *Server) loadRulePack(profile string, override *rules.RulePack) (rules.RulePack, error) {
	if override != nil && len(override.Rules) > 0 {
		return *override, nil
	}
	path, ok := s.profilePack[profile]
	if !ok {
		return rules.RulePack{}, fmt.Errorf("no default rule pack for profile %s", profile)
	}
	return rules.LoadRulePack(path)
}

func toRef(art Artifact) ArtifactRef {
	return ArtifactRef{
		ID:          art.ID,
		Name:        art.Name,
		ContentType: art.ContentType,
		Size:        art.Size,
		Kind:        art.Kind,
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func guessContentType(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "application/yaml"
	case ".ndjson":
		return "application/x-ndjson"
	case ".pdf":
		return "application/pdf"
	case ".tmats", ".tmt", ".txt":
		return "text/plain"
	case ".ch10", ".df10", ".tf10":
		return "application/octet-stream"
	default:
		return "application/octet-stream"
	}
}

func randomID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		now := time.Now().UTC()
		return fmt.Sprintf("%d%06d", now.UnixNano(), os.Getpid())
	}
	return hex.EncodeToString(b[:])
}

func (s *Server) listArtifacts() []ArtifactRef {
	s.artifacts.mu.RLock()
	refs := make([]ArtifactRef, 0, len(s.artifacts.entries))
	for _, art := range s.artifacts.entries {
		refs = append(refs, toRef(art))
	}
	s.artifacts.mu.RUnlock()
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	return refs
}
