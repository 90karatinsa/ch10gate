package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"example.com/ch10gate/internal/common"
	"example.com/ch10gate/internal/manifest"
)

func TestHandleManifestSignAndVerify(t *testing.T) {
	tmp := t.TempDir()
	storage := filepath.Join(tmp, "storage")
	packs := make([]ProfilePack, 0, len(RequiredProfiles))
	for _, id := range RequiredProfiles {
		rulesPath := filepath.Join(tmp, id+".json")
		if err := os.WriteFile(rulesPath, []byte("{}"), 0o644); err != nil {
			t.Fatalf("write rules %s: %v", id, err)
		}
		packs = append(packs, ProfilePack{ID: id, Rules: rulesPath})
	}

	keyPEM, certPEM := generateTestSigner(t)
	keyPath := filepath.Join(tmp, "signer.key")
	certPath := filepath.Join(tmp, "signer.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	srv, err := NewServer(Options{
		StorageDir:   storage,
		ProfilePacks: packs,
		ManifestSigning: ManifestSigningOptions{
			PrivateKeyPath:  keyPath,
			CertificatePath: certPath,
		},
	})
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

	inputPath := filepath.Join(tmp, "input.bin")
	if err := os.WriteFile(inputPath, []byte("manifest test payload"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	reqBody := map[string]any{
		"inputs":  []string{inputPath},
		"shaAlgo": "sha256",
		"sign":    true,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := http.Post(ts.URL+"/manifest", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /manifest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/manifest status %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Manifest          manifest.Manifest `json:"manifest"`
		ManifestArtifact  ArtifactRef       `json:"manifestArtifact"`
		SignatureArtifact *ArtifactRef      `json:"signatureArtifact"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Manifest.Signature == nil {
		t.Fatalf("expected manifest signature metadata")
	}
	if out.SignatureArtifact == nil {
		t.Fatalf("expected signature artifact")
	}

	manifestPath := filepath.Join(tmp, "manifest.json")
	downloadArtifact(t, ts.URL, out.ManifestArtifact.ID, manifestPath)
	signaturePath := filepath.Join(tmp, "manifest.jws")
	downloadArtifact(t, ts.URL, out.SignatureArtifact.ID, signaturePath)

	root := repoRoot(t)
	licensePath := filepath.Join(tmp, "license.json")
	writeTestLicense(t, licensePath)
	cmd := exec.Command("go", "run", "./cmd/ch10ctl", "verify-signature", "--manifest", manifestPath, "--jws", signaturePath, "--cert", certPath)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CH10CTL_LICENSE_PATH="+licensePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify-signature failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "Signature OK") {
		t.Fatalf("unexpected verify output: %s", output)
	}
}

func downloadArtifact(t *testing.T, baseURL, id, outPath string) {
	t.Helper()
	resp, err := http.Get(baseURL + "/artifacts/" + id)
	if err != nil {
		t.Fatalf("download artifact %s: %v", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("artifact status %d: %s", resp.StatusCode, string(body))
	}
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create %s: %v", outPath, err)
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		t.Fatalf("copy artifact %s: %v", id, err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	root := filepath.Clean(filepath.Join(dir, "..", ".."))
	return root
}

func generateTestSigner(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Manifest Signer", Organization: []string{"ch10gate"}},
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
	return keyPEM, certPEM
}

func writeTestLicense(t *testing.T, path string) {
	t.Helper()
	machine, err := common.MachineFingerprint()
	if err != nil {
		t.Fatalf("MachineFingerprint: %v", err)
	}
	expiry := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02")
	mac := hmac.New(sha256.New, []byte("ch10gate-license-secret"))
	mac.Write([]byte(machine))
	mac.Write([]byte("|"))
	mac.Write([]byte(expiry))
	signature := hex.EncodeToString(mac.Sum(nil))
	payload := map[string]string{
		"machine":   machine,
		"expiry":    expiry,
		"signature": signature,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal license: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write license: %v", err)
	}
}
