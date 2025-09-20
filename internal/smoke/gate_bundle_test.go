package smoke

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func writeSigner(t *testing.T, keyPath, certPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Gate Bundle Signer", Organization: []string{"ch10gate"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("WriteFile cert: %v", err)
	}
}

func TestGateBundleFailsWithoutSigningMaterial(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("bash", "scripts/gate_bundle.sh")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GATE_BUNDLE_SIGNING_KEY=", "GATE_BUNDLE_SIGNING_CERT=")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected gate_bundle.sh to fail without signing material\n%s", output)
	}
	if !bytes.Contains(output, []byte("bundle signing material not configured")) {
		t.Fatalf("unexpected stderr when signing material missing:\n%s", output)
	}
}

func TestGateBundleBuildsWithSigningMaterial(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping gate bundle smoke test in short mode")
	}
	root := repoRoot(t)
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "signing.key")
	certPath := filepath.Join(tmp, "signing.crt")
	writeSigner(t, keyPath, certPath)

	bundleDir := filepath.Join(root, "DIST")
	t.Cleanup(func() {
		os.RemoveAll(bundleDir)
	})

	env := append(os.Environ(),
		"GATE_BUNDLE_SIGNING_KEY="+keyPath,
		"GATE_BUNDLE_SIGNING_CERT="+certPath,
		"VERSION=smoke-test",
	)

	cmd := exec.Command("bash", "scripts/gate_bundle.sh")
	cmd.Dir = root
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gate_bundle.sh failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("[gate-bundle] verifying manifest signature")) {
		t.Fatalf("missing verification step in output:\n%s", output)
	}

	manifestPath := filepath.Join(root, "DIST", "ch10gate_bundle", "manifest.json")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("manifest.json missing: %v", err)
	}
	sigPath := filepath.Join(root, "DIST", "ch10gate_bundle", "SIGNATURE.jws")
	if _, err := os.Stat(sigPath); err != nil {
		t.Fatalf("SIGNATURE.jws missing: %v", err)
	}
}
