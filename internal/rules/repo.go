package rules

import (
	"archive/zip"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"example.com/ch10gate/internal/crypto"
)

const (
	repoRulepacksDir  = "rulepacks"
	repoTruststoreDir = "truststore"
	repoConfigFile    = "config.json"
	rulePackFileName  = "rulepack.json"
	signatureFileName = "signature.jws"
)

// Repository manages installation and discovery of rule packs.
type Repository struct {
	root string
}

// RulePackRef identifies a rule pack by id and version.
type RulePackRef struct {
	RulePackId string `json:"rulePackId"`
	Version    string `json:"version"`
}

// InstalledRulePack represents a rule pack stored in the repository.
type InstalledRulePack struct {
	RulePack RulePack
	Dir      string
	Signed   bool
	Path     string
	Signer   string
}

type repoConfig struct {
	DefaultByProfile map[string]RulePackRef `json:"defaultByProfile"`
}

// DefaultRepository returns the repository rooted in ~/.ch10gate/rules.
func DefaultRepository() (*Repository, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return OpenRepository(filepath.Join(home, ".ch10gate", "rules"))
}

// OpenRepository creates a Repository rooted at path and ensures the required
// subdirectories exist.
func OpenRepository(path string) (*Repository, error) {
	if err := os.MkdirAll(filepath.Join(path, repoRulepacksDir), 0o755); err != nil {
		return nil, fmt.Errorf("create rulepacks dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(path, repoTruststoreDir), 0o755); err != nil {
		return nil, fmt.Errorf("create truststore dir: %w", err)
	}
	return &Repository{root: path}, nil
}

// Root returns the root directory of the repository.
func (r *Repository) Root() string {
	if r == nil {
		return ""
	}
	return r.root
}

// InstallPackage installs a .rpkg.zip archive into the repository.
func (r *Repository) InstallPackage(archivePath string, allowUnsigned bool) (InstalledRulePack, error) {
	var installed InstalledRulePack
	if r == nil {
		return installed, errors.New("nil repository")
	}
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return installed, fmt.Errorf("open archive: %w", err)
	}
	defer zr.Close()

	var rulePackBytes, sigBytes []byte
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		switch base {
		case rulePackFileName:
			rulePackBytes, err = readZipFile(f)
			if err != nil {
				return installed, fmt.Errorf("read %s: %w", rulePackFileName, err)
			}
		case signatureFileName:
			sigBytes, err = readZipFile(f)
			if err != nil {
				return installed, fmt.Errorf("read %s: %w", signatureFileName, err)
			}
		}
	}
	if len(rulePackBytes) == 0 {
		return installed, errors.New("rulepack.json not found in archive")
	}
	if len(sigBytes) == 0 && !allowUnsigned {
		return installed, errors.New("signature.jws not found in archive")
	}

	var rp RulePack
	if err := json.Unmarshal(rulePackBytes, &rp); err != nil {
		return installed, fmt.Errorf("parse rulepack.json: %w", err)
	}
	if rp.RulePackId == "" || rp.Version == "" {
		return installed, errors.New("rulepack missing id or version")
	}
	if err := validatePathComponent(rp.RulePackId); err != nil {
		return installed, fmt.Errorf("invalid rule pack id: %w", err)
	}
	if err := validatePathComponent(rp.Version); err != nil {
		return installed, fmt.Errorf("invalid rule pack version: %w", err)
	}

	var signer string
	if len(sigBytes) != 0 {
		cert, err := r.verifySignatureBytes(rulePackBytes, sigBytes)
		if err != nil {
			return installed, fmt.Errorf("verify signature: %w", err)
		}
		signer = cert.Subject.String()
	}

	dir := r.packageDir(rp.RulePackId, rp.Version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return installed, fmt.Errorf("create package dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, rulePackFileName), rulePackBytes, 0o644); err != nil {
		return installed, fmt.Errorf("write rulepack.json: %w", err)
	}
	if len(sigBytes) != 0 {
		if err := os.WriteFile(filepath.Join(dir, signatureFileName), sigBytes, 0o644); err != nil {
			return installed, fmt.Errorf("write signature.jws: %w", err)
		}
	} else {
		_ = os.Remove(filepath.Join(dir, signatureFileName))
	}

	installed = InstalledRulePack{
		RulePack: rp,
		Dir:      dir,
		Signed:   len(sigBytes) != 0,
		Path:     filepath.Join(dir, rulePackFileName),
		Signer:   signer,
	}
	return installed, nil
}

// ListInstalled returns the rule packs currently installed in the repository.
func (r *Repository) ListInstalled() ([]InstalledRulePack, error) {
	if r == nil {
		return nil, errors.New("nil repository")
	}
	base := filepath.Join(r.root, repoRulepacksDir)
	entries, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var result []InstalledRulePack
	for _, idEntry := range entries {
		if !idEntry.IsDir() {
			continue
		}
		id := idEntry.Name()
		versionDir := filepath.Join(base, id)
		versEntries, err := os.ReadDir(versionDir)
		if err != nil {
			return nil, err
		}
		for _, vEntry := range versEntries {
			if !vEntry.IsDir() {
				continue
			}
			version := vEntry.Name()
			rpPath := filepath.Join(versionDir, version, rulePackFileName)
			bytes, err := os.ReadFile(rpPath)
			if err != nil {
				continue
			}
			var rp RulePack
			if err := json.Unmarshal(bytes, &rp); err != nil {
				continue
			}
			sigPath := filepath.Join(versionDir, version, signatureFileName)
			_, err = os.Stat(sigPath)
			signed := err == nil
			result = append(result, InstalledRulePack{
				RulePack: rp,
				Dir:      filepath.Join(versionDir, version),
				Signed:   signed,
				Path:     rpPath,
			})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].RulePack.RulePackId == result[j].RulePack.RulePackId {
			return compareVersions(result[i].RulePack.Version, result[j].RulePack.Version) < 0
		}
		return result[i].RulePack.RulePackId < result[j].RulePack.RulePackId
	})
	return result, nil
}

// Remove removes a rule pack identified by id and version from the repository.
func (r *Repository) Remove(id, version string) error {
	if r == nil {
		return errors.New("nil repository")
	}
	if err := validatePathComponent(id); err != nil {
		return fmt.Errorf("invalid rule pack id: %w", err)
	}
	if err := validatePathComponent(version); err != nil {
		return fmt.Errorf("invalid rule pack version: %w", err)
	}
	dir := r.packageDir(id, version)
	if _, err := os.Stat(dir); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	cfg, err := r.loadConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(cfg.DefaultByProfile) == 0 {
		return nil
	}
	changed := false
	for profile, ref := range cfg.DefaultByProfile {
		if ref.RulePackId == id && ref.Version == version {
			delete(cfg.DefaultByProfile, profile)
			changed = true
		}
	}
	if changed {
		if err := r.saveConfig(cfg); err != nil {
			return err
		}
	}
	return nil
}

// Verify re-validates the stored signature of a rule pack.
func (r *Repository) Verify(id, version string) error {
	if r == nil {
		return errors.New("nil repository")
	}
	if err := validatePathComponent(id); err != nil {
		return fmt.Errorf("invalid rule pack id: %w", err)
	}
	if err := validatePathComponent(version); err != nil {
		return fmt.Errorf("invalid rule pack version: %w", err)
	}
	dir := r.packageDir(id, version)
	rpBytes, err := os.ReadFile(filepath.Join(dir, rulePackFileName))
	if err != nil {
		return fmt.Errorf("read rulepack: %w", err)
	}
	sigBytes, err := os.ReadFile(filepath.Join(dir, signatureFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("rule pack is unsigned")
		}
		return fmt.Errorf("read signature: %w", err)
	}
	if _, err := r.verifySignatureBytes(rpBytes, sigBytes); err != nil {
		return err
	}
	return nil
}

// Load returns the rule pack identified by id and version.
func (r *Repository) Load(id, version string, allowUnsigned bool) (RulePack, RulePackSource, error) {
	var rp RulePack
	var source RulePackSource
	if r == nil {
		return rp, source, errors.New("nil repository")
	}
	if err := validatePathComponent(id); err != nil {
		return rp, source, fmt.Errorf("invalid rule pack id: %w", err)
	}
	if err := validatePathComponent(version); err != nil {
		return rp, source, fmt.Errorf("invalid rule pack version: %w", err)
	}
	dir := r.packageDir(id, version)
	rpPath := filepath.Join(dir, rulePackFileName)
	bytes, err := os.ReadFile(rpPath)
	if err != nil {
		return rp, source, err
	}
	sigBytes, err := os.ReadFile(filepath.Join(dir, signatureFileName))
	unsigned := false
	signer := ""
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if !allowUnsigned {
				return rp, source, errors.New("rule pack is unsigned; use allow-unsigned option")
			}
			unsigned = true
		} else {
			return rp, source, err
		}
	} else {
		cert, err := r.verifySignatureBytes(bytes, sigBytes)
		if err != nil {
			return rp, source, fmt.Errorf("verify signature: %w", err)
		}
		signer = cert.Subject.String()
	}
	if err := json.Unmarshal(bytes, &rp); err != nil {
		return rp, source, fmt.Errorf("parse rulepack: %w", err)
	}
	if rp.RulePackId != id || rp.Version != version {
		return rp, source, errors.New("rule pack metadata does not match requested id/version")
	}
	source = RulePackSource{
		FromRepository: true,
		RulePackId:     id,
		Version:        version,
		Path:           rpPath,
		Unsigned:       unsigned,
		Signer:         signer,
	}
	return rp, source, nil
}

// DefaultForProfile returns the configured default rule pack for the given profile.
func (r *Repository) DefaultForProfile(profile string) (RulePackRef, bool, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RulePackRef{}, false, nil
		}
		return RulePackRef{}, false, err
	}
	ref, ok := cfg.DefaultByProfile[profile]
	return ref, ok, nil
}

// SetDefaultForProfile updates the default rule pack for profile.
func (r *Repository) SetDefaultForProfile(profile string, ref RulePackRef) error {
	if r == nil {
		return errors.New("nil repository")
	}
	if err := validatePathComponent(ref.RulePackId); err != nil {
		return fmt.Errorf("invalid rule pack id: %w", err)
	}
	if err := validatePathComponent(ref.Version); err != nil {
		return fmt.Errorf("invalid rule pack version: %w", err)
	}
	cfg, err := r.loadConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if cfg.DefaultByProfile == nil {
		cfg.DefaultByProfile = make(map[string]RulePackRef)
	}
	cfg.DefaultByProfile[profile] = ref
	return r.saveConfig(cfg)
}

func (r *Repository) latestVersionFor(id string) (string, error) {
	if err := validatePathComponent(id); err != nil {
		return "", fmt.Errorf("invalid rule pack id: %w", err)
	}
	dir := filepath.Join(r.root, repoRulepacksDir, id)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	best := ""
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ver := e.Name()
		if best == "" || compareVersions(ver, best) > 0 {
			best = ver
		}
	}
	return best, nil
}

// Defaults returns a copy of the configured default mappings.
func (r *Repository) Defaults() (map[string]RulePackRef, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]RulePackRef{}, nil
		}
		return nil, err
	}
	out := make(map[string]RulePackRef, len(cfg.DefaultByProfile))
	for k, v := range cfg.DefaultByProfile {
		out[k] = v
	}
	return out, nil
}

func (r *Repository) packageDir(id, version string) string {
	return filepath.Join(r.root, repoRulepacksDir, id, version)
}

func (r *Repository) verifySignatureBytes(payload, sig []byte) (*x509.Certificate, error) {
	pool, err := r.loadTrustStore()
	if err != nil {
		return nil, err
	}
	var jws crypto.JWS
	if err := json.Unmarshal(sig, &jws); err != nil {
		return nil, fmt.Errorf("parse signature: %w", err)
	}
	cert, err := crypto.VerifyDetachedJWSWithX5C(payload, jws, pool)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (r *Repository) loadTrustStore() (*x509.CertPool, error) {
	dir := filepath.Join(r.root, repoTruststoreDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read truststore: %w", err)
	}
	pool := x509.NewCertPool()
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read truststore cert %s: %w", entry.Name(), err)
		}
		rest := data
		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse truststore cert %s: %w", entry.Name(), err)
			}
			pool.AddCert(cert)
			count++
		}
	}
	if count == 0 {
		return nil, errors.New("truststore is empty")
	}
	return pool, nil
}

func (r *Repository) loadConfig() (repoConfig, error) {
	var cfg repoConfig
	if r == nil {
		return cfg, errors.New("nil repository")
	}
	path := filepath.Join(r.root, repoConfigFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (r *Repository) saveConfig(cfg repoConfig) error {
	if r == nil {
		return errors.New("nil repository")
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(r.root, repoConfigFile)
	return os.WriteFile(path, data, 0o644)
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func validatePathComponent(s string) error {
	if s == "" {
		return errors.New("empty string")
	}
	if strings.Contains(s, string(os.PathSeparator)) || strings.Contains(s, "/") {
		return errors.New("contains path separator")
	}
	if s == "." || s == ".." {
		return errors.New("invalid component")
	}
	if strings.Contains(s, "..") {
		cleaned := filepath.Clean(s)
		if cleaned != s {
			return errors.New("invalid path component")
		}
	}
	return nil
}

func compareVersions(a, b string) int {
	if a == b {
		return 0
	}
	ap := parseVersionParts(a)
	bp := parseVersionParts(b)
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		ai := 0
		if i < len(ap) {
			ai = ap[i]
		}
		bi := 0
		if i < len(bp) {
			bi = bp[i]
		}
		if ai > bi {
			return 1
		}
		if ai < bi {
			return -1
		}
	}
	if len(ap) > len(bp) {
		return 1
	}
	if len(ap) < len(bp) {
		return -1
	}
	return strings.Compare(a, b)
}

func parseVersionParts(s string) []int {
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			out = append(out, 0)
			continue
		}
		if v, err := strconv.Atoi(p); err == nil {
			out = append(out, v)
		} else {
			return []int{0}
		}
	}
	return out
}
