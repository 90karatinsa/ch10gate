package update

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultInstallRoot is where versioned releases are stored.
	DefaultInstallRoot = "/opt/ch10gate"
	// DefaultBinDir is where CLI-visible symlinks are created.
	DefaultBinDir = "/usr/local/bin"
	// DefaultCertPath is the trusted signer certificate.
	DefaultCertPath = "/etc/ch10d/update_cert.pem"
	currentLinkName = "current"
)

// Options configure an Installer.
type Options struct {
	InstallRoot string
	BinDir      string
	CertPath    string
}

// Result captures information about a successful installation.
type Result struct {
	Version         string
	PreviousVersion string
	ReleasePath     string
}

// Installer applies signed update packages to a versioned install root.
type Installer struct {
	opts Options
}

// NewInstaller returns an Installer with sane defaults.
func NewInstaller(opts Options) (*Installer, error) {
	if opts.InstallRoot == "" {
		opts.InstallRoot = DefaultInstallRoot
	}
	if opts.BinDir == "" {
		opts.BinDir = DefaultBinDir
	}
	if opts.CertPath == "" {
		if env := os.Getenv("CH10_UPDATE_CERT"); env != "" {
			opts.CertPath = env
		} else {
			opts.CertPath = DefaultCertPath
		}
	}
	return &Installer{opts: opts}, nil
}

// InstallFromArchive verifies and installs the provided update zip archive.
func (i *Installer) InstallFromArchive(archivePath string) (Result, error) {
	if archivePath == "" {
		return Result{}, errors.New("empty archive path")
	}
	certPEM, err := os.ReadFile(i.opts.CertPath)
	if err != nil {
		return Result{}, fmt.Errorf("read cert: %w", err)
	}
	if err := os.MkdirAll(i.opts.InstallRoot, 0o755); err != nil {
		return Result{}, fmt.Errorf("install root: %w", err)
	}
	releasesDir := filepath.Join(i.opts.InstallRoot, "releases")
	if err := os.MkdirAll(releasesDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("releases dir: %w", err)
	}
	tempDir, err := os.MkdirTemp(releasesDir, "pending-")
	if err != nil {
		return Result{}, fmt.Errorf("extract temp: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tempDir)
		}
	}()
	if err := extractArchive(archivePath, tempDir); err != nil {
		return Result{}, err
	}
	pkg, err := verifyExtracted(tempDir, certPEM)
	if err != nil {
		return Result{}, err
	}
	currentVersion, err := i.InstalledVersion()
	if err != nil {
		return Result{}, fmt.Errorf("read installed version: %w", err)
	}
	if currentVersion != "" {
		if compareVersions(pkg.Version, currentVersion) <= 0 {
			return Result{}, fmt.Errorf("update version %s is not newer than installed %s", pkg.Version, currentVersion)
		}
	}
	releaseDir := filepath.Join(releasesDir, pkg.Version)
	if _, err := os.Stat(releaseDir); err == nil {
		return Result{}, fmt.Errorf("version %s already installed", pkg.Version)
	}
	if err := os.Rename(tempDir, releaseDir); err != nil {
		return Result{}, fmt.Errorf("activate release: %w", err)
	}
	cleanup = false
	if err := i.swapCurrentSymlink(releaseDir); err != nil {
		return Result{}, err
	}
	if err := i.ensureBinSymlinks(releaseDir); err != nil {
		return Result{}, err
	}
	return Result{Version: pkg.Version, PreviousVersion: currentVersion, ReleasePath: releaseDir}, nil
}

// InstalledVersion returns the currently active version, if any.
func (i *Installer) InstalledVersion() (string, error) {
	currentPath := filepath.Join(i.opts.InstallRoot, currentLinkName)
	target, err := os.Readlink(currentPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(currentPath), target)
	}
	versionBytes, err := os.ReadFile(filepath.Join(target, "VERSION"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(versionBytes)), nil
}

func (i *Installer) swapCurrentSymlink(releaseDir string) error {
	currentPath := filepath.Join(i.opts.InstallRoot, currentLinkName)
	tmp := currentPath + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(releaseDir, tmp); err != nil {
		return fmt.Errorf("create tmp symlink: %w", err)
	}
	if err := os.Rename(tmp, currentPath); err != nil {
		return fmt.Errorf("activate symlink: %w", err)
	}
	return nil
}

func (i *Installer) ensureBinSymlinks(releaseDir string) error {
	binDir := filepath.Join(releaseDir, "bin")
	entries, err := os.ReadDir(binDir)
	if err != nil {
		return fmt.Errorf("read bin dir: %w", err)
	}
	if err := os.MkdirAll(i.opts.BinDir, 0o755); err != nil {
		return fmt.Errorf("bin dir: %w", err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		name := entry.Name()
		target := filepath.Join(i.opts.InstallRoot, currentLinkName, "bin", name)
		linkPath := filepath.Join(i.opts.BinDir, name)
		tmp := linkPath + ".tmp"
		_ = os.Remove(tmp)
		if err := os.Symlink(target, tmp); err != nil {
			return fmt.Errorf("create symlink for %s: %w", name, err)
		}
		if err := os.Rename(tmp, linkPath); err != nil {
			return fmt.Errorf("activate symlink for %s: %w", name, err)
		}
	}
	return nil
}

func extractArchive(archivePath, dest string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer r.Close()
	for _, file := range r.File {
		name := filepath.Clean(file.Name)
		if name == "." || strings.HasPrefix(name, "../") || strings.Contains(name, ":") {
			return fmt.Errorf("archive entry %q invalid", file.Name)
		}
		if strings.HasPrefix(name, "__MACOSX") {
			continue
		}
		targetPath := filepath.Join(dest, name)
		rel, err := filepath.Rel(dest, targetPath)
		if err != nil {
			return fmt.Errorf("normalise %s: %w", file.Name, err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("archive entry %q escapes destination", file.Name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", targetPath, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(targetPath), err)
		}
		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("open entry %s: %w", file.Name, err)
		}
		mode := file.Mode()
		if mode == 0 {
			mode = 0o644
		}
		out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			rc.Close()
			return fmt.Errorf("create %s: %w", targetPath, err)
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return fmt.Errorf("extract %s: %w", file.Name, err)
		}
		out.Close()
		rc.Close()
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
		v := 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				v = -1
				break
			}
			v = v*10 + int(ch-'0')
		}
		if v < 0 {
			return []int{0}
		}
		out = append(out, v)
	}
	return out
}

// FindArchive locates a single .update.zip archive within dir.
func FindArchive(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("empty directory")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	matches := make([]string, 0, 1)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(strings.ToLower(name), ".update.zip") {
			matches = append(matches, filepath.Join(dir, name))
		}
	}
	if len(matches) == 0 {
		return "", errors.New("no .update.zip archive found")
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("multiple .update.zip archives found in %s", dir)
	}
	return matches[0], nil
}
