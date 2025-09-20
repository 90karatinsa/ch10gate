package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"example.com/ch10gate/internal/common"
	"example.com/ch10gate/internal/crypto"
	"example.com/ch10gate/internal/manifest"
)

// Package represents the contents of an update package after it has been
// extracted to disk and verified against its manifest signature.
type Package struct {
	Root     string
	Version  string
	Manifest manifest.Manifest
}

// verifyExtracted performs signature verification and structural validation on
// the extracted update directory.
func verifyExtracted(root string, certPEM []byte) (Package, error) {
	if root == "" {
		return Package{}, errors.New("empty root")
	}
	manifestPath := filepath.Join(root, "MANIFEST.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return Package{}, fmt.Errorf("read manifest: %w", err)
	}
	sigPath := filepath.Join(root, "SIGNATURE.jws")
	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		return Package{}, fmt.Errorf("read signature: %w", err)
	}
	jws, err := crypto.ParseDetachedJWS(sigBytes)
	if err != nil {
		return Package{}, fmt.Errorf("parse jws: %w", err)
	}
	if err := crypto.VerifyDetachedJWS(manifestBytes, jws, certPEM); err != nil {
		return Package{}, fmt.Errorf("verify signature: %w", err)
	}
	var mani manifest.Manifest
	if err := json.Unmarshal(manifestBytes, &mani); err != nil {
		return Package{}, fmt.Errorf("parse manifest: %w", err)
	}
	if mani.ShaAlgo != "sha256" {
		return Package{}, fmt.Errorf("unsupported manifest algorithm %q", mani.ShaAlgo)
	}
	if len(mani.Items) == 0 {
		return Package{}, errors.New("manifest has no items")
	}
	if err := validateManifestItems(root, mani.Items); err != nil {
		return Package{}, err
	}
	versionPath := filepath.Join(root, "VERSION")
	versionBytes, err := os.ReadFile(versionPath)
	if err != nil {
		return Package{}, fmt.Errorf("read version: %w", err)
	}
	version := strings.TrimSpace(string(versionBytes))
	if version == "" {
		return Package{}, errors.New("empty version in package")
	}
	if err := ensureRequiredFiles(root); err != nil {
		return Package{}, err
	}
	return Package{Root: root, Version: version, Manifest: mani}, nil
}

func ensureRequiredFiles(root string) error {
	required := []string{"LICENSE", "VERSION", "bin"}
	for _, name := range required {
		path := filepath.Join(root, name)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("package missing %s: %w", name, err)
		}
		if name == "bin" && !info.IsDir() {
			return errors.New("package bin entry is not a directory")
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "bin"))
	if err != nil {
		return fmt.Errorf("read bin dir: %w", err)
	}
	hasBinary := false
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			hasBinary = true
			break
		}
	}
	if !hasBinary {
		return errors.New("package bin directory empty")
	}
	return nil
}

func validateManifestItems(root string, items []manifest.Item) error {
	seenVersion := false
	seenLicense := false
	binEntries := 0
	for _, item := range items {
		if strings.TrimSpace(item.Path) == "" {
			return errors.New("manifest item missing path")
		}
		cleaned := filepath.Clean(item.Path)
		if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			return fmt.Errorf("manifest item %q escapes package root", item.Path)
		}
		if filepath.IsAbs(cleaned) {
			return fmt.Errorf("manifest item %q is absolute", item.Path)
		}
		path := filepath.Join(root, cleaned)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("manifest item %q: %w", item.Path, err)
		}
		if info.IsDir() {
			return fmt.Errorf("manifest item %q is a directory", item.Path)
		}
		hash, size, err := common.Sha256OfFile(path)
		if err != nil {
			return fmt.Errorf("hash %q: %w", item.Path, err)
		}
		if hash != item.Sha256 {
			return fmt.Errorf("manifest mismatch for %s", item.Path)
		}
		if size != item.Size {
			return fmt.Errorf("manifest size mismatch for %s", item.Path)
		}
		switch cleaned {
		case "VERSION":
			seenVersion = true
		case "LICENSE":
			seenLicense = true
		}
		if strings.HasPrefix(cleaned, "bin/") {
			binEntries++
		}
	}
	if !seenVersion {
		return errors.New("manifest missing VERSION entry")
	}
	if !seenLicense {
		return errors.New("manifest missing LICENSE entry")
	}
	if binEntries == 0 {
		return errors.New("manifest missing binaries")
	}
	return nil
}
