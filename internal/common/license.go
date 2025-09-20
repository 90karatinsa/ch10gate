package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// License represents a validated offline license file.
type License struct {
	MachineHash string
	Expiry      time.Time
	Path        string
}

var (
	cachedLicense *License
	licenseErr    error
	licenseOnce   sync.Once
)

const (
	defaultLicenseFilename = "license.json"
	defaultLicenseKey      = "ch10gate-license-secret"
)

// RequireValidLicense ensures that a valid license is available before executing
// any commands. It returns the parsed license or an error that explains why the
// license is invalid.
func RequireValidLicense() (*License, error) {
	licenseOnce.Do(func() {
		cachedLicense, licenseErr = loadAndValidateLicense()
	})
	return cachedLicense, licenseErr
}

func loadAndValidateLicense() (*License, error) {
	path, err := resolveLicensePath()
	if err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read license: %w", err)
	}

	var payload struct {
		Machine   string `json:"machine"`
		Expiry    string `json:"expiry"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("parse license json: %w", err)
	}

	payload.Machine = strings.TrimSpace(payload.Machine)
	payload.Expiry = strings.TrimSpace(payload.Expiry)
	payload.Signature = strings.TrimSpace(payload.Signature)

	if payload.Machine == "" {
		return nil, errors.New("license machine hash is empty")
	}
	if payload.Expiry == "" {
		return nil, errors.New("license expiry is empty")
	}
	if payload.Signature == "" {
		return nil, errors.New("license signature is empty")
	}

	expiryDate, err := time.Parse("2006-01-02", payload.Expiry)
	if err != nil {
		return nil, fmt.Errorf("invalid expiry format: %w", err)
	}
	// Expiry is inclusive for the given day.
	expiryCutoff := expiryDate.Add(24 * time.Hour)
	now := time.Now().UTC()
	if now.After(expiryCutoff) {
		return nil, fmt.Errorf("license expired on %s", payload.Expiry)
	}

	machineHash, err := MachineFingerprint()
	if err != nil {
		return nil, fmt.Errorf("compute machine hash: %w", err)
	}
	if !strings.EqualFold(machineHash, payload.Machine) {
		return nil, fmt.Errorf("license machine hash mismatch (expected %s, this machine %s)", payload.Machine, machineHash)
	}

	key := []byte(defaultLicenseKey)
	if env := strings.TrimSpace(os.Getenv("CH10CTL_LICENSE_KEY")); env != "" {
		key = []byte(env)
	}
	expectedSig := computeLicenseSignature(payload.Machine, payload.Expiry, key)
	providedSig, err := hex.DecodeString(payload.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid license signature encoding: %w", err)
	}
	if !hmac.Equal(providedSig, expectedSig) {
		return nil, errors.New("license signature verification failed")
	}

	return &License{
		MachineHash: machineHash,
		Expiry:      expiryCutoff,
		Path:        path,
	}, nil
}

func computeLicenseSignature(machine, expiry string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(machine))
	mac.Write([]byte("|"))
	mac.Write([]byte(expiry))
	return mac.Sum(nil)
}

func resolveLicensePath() (string, error) {
	candidates := licensePathCandidates()
	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			return cand, nil
		}
	}
	if len(candidates) == 0 {
		return "", errors.New("no license path configured")
	}
	return "", fmt.Errorf("license file not found (checked: %s)", strings.Join(candidates, ", "))
}

func licensePathCandidates() []string {
	seen := map[string]struct{}{}
	var paths []string
	add := func(path string) {
		if path == "" {
			return
		}
		cleaned := filepath.Clean(path)
		if _, ok := seen[cleaned]; ok {
			return
		}
		seen[cleaned] = struct{}{}
		paths = append(paths, cleaned)
	}

	if env := strings.TrimSpace(os.Getenv("CH10CTL_LICENSE_PATH")); env != "" {
		add(env)
	}

	if cwd, err := os.Getwd(); err == nil {
		add(filepath.Join(cwd, defaultLicenseFilename))
	}
	if exe, err := os.Executable(); err == nil {
		add(filepath.Join(filepath.Dir(exe), defaultLicenseFilename))
	}

	return paths
}

// MachineFingerprint produces a stable hash for the current machine using the
// hostname and MAC addresses. It can be shared with the vendor to generate a
// license file.
func MachineFingerprint() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	var components []string
	components = append(components, strings.ToLower(hostname))
	for _, iface := range interfaces {
		if (iface.Flags&net.FlagLoopback) != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		components = append(components, strings.ToLower(iface.HardwareAddr.String()))
	}
	if len(components) == 1 {
		// No network interfaces were added; include OS as a weak fallback.
		components = append(components, strings.ToLower(runtime.GOOS))
	}

	hash := sha256.Sum256([]byte(strings.Join(components, "|")))
	return hex.EncodeToString(hash[:]), nil
}

// SignLicenseForTesting is exported to help integration tests build synthetic
// licenses without the vendor tooling.
func SignLicenseForTesting(machineHash, expiry string, key []byte) string {
	sig := computeLicenseSignature(machineHash, expiry, key)
	return hex.EncodeToString(sig)
}
