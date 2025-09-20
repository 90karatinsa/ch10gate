package tmats

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseStringCapturesEntries(t *testing.T) {
	raw := "# Comment line\nR-1\\CHE-1:1; R-1\\CHE-1:2;\nR-1\\CDT-1:PCM;# trailing\n"
	doc := parseString(raw)
	if doc == nil {
		t.Fatalf("parseString returned nil")
	}
	if len(doc.Comments()) != 1 {
		t.Fatalf("expected 1 comment, got %d", len(doc.Comments()))
	}
	if val, ok := doc.Get("R-1\\CHE-1"); !ok || val != "2" {
		t.Fatalf("expected CHE-1=2, got %q", val)
	}
	keys := doc.Keys()
	if len(keys) != 2 || keys[0] != "R-1\\CHE-1" || keys[1] != "R-1\\CDT-1" {
		t.Fatalf("unexpected keys: %v", keys)
	}
}

func TestDocumentSetGetDelete(t *testing.T) {
	doc := parseString("")
	if changed := doc.Set("R-1\\CHE-1", "1"); !changed {
		t.Fatalf("expected Set to add value")
	}
	if changed := doc.Set("R-1\\CHE-1", "1"); changed {
		t.Fatalf("expected Set to no-op when same value")
	}
	if val, ok := doc.Get("R-1\\CHE-1"); !ok || val != "1" {
		t.Fatalf("unexpected get: %q", val)
	}
	if !doc.Delete("R-1\\CHE-1") {
		t.Fatalf("expected delete to succeed")
	}
	if doc.Delete("R-1\\CHE-1") {
		t.Fatalf("expected delete to fail second time")
	}
}

func TestCommentHelpers(t *testing.T) {
	doc := parseString("# First\n")
	if !doc.AddComment("# Second") {
		t.Fatalf("expected new comment")
	}
	if doc.AddComment("Second") {
		t.Fatalf("duplicate comment should not be added")
	}
	if !doc.EnsureCommentWithTag("TAG", "# TAG added") {
		t.Fatalf("expected comment with tag to be added")
	}
	if doc.EnsureCommentWithTag("TAG", "# TAG added") {
		t.Fatalf("duplicate tag should not be added")
	}
}

func TestStringSerialization(t *testing.T) {
	raw := "R-1\\CHE-1:1;\nG\\SHA:deadbeef;\n"
	doc := parseString(raw)
	without := doc.StringWithoutDigest()
	if strings.Contains(without, "G\\SHA") {
		t.Fatalf("digest should be omitted, got %q", without)
	}
	digest, err := doc.ComputeDigest()
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	serialized := WithDigest(doc, digest)
	if !strings.Contains(serialized, digest) {
		t.Fatalf("serialized document missing digest")
	}
}

func TestDataTypeAndTimeFormatNames(t *testing.T) {
	if got := DataTypeName(0x08); got != "PCM" {
		t.Fatalf("expected PCM, got %q", got)
	}
	if got := DataTypeName(0x99); got != "0x99" {
		t.Fatalf("expected hex name, got %q", got)
	}
	if got := TimeFormatName(0x00); got != "IRIG-106" {
		t.Fatalf("expected IRIG-106, got %q", got)
	}
	if got := TimeFormatName(0x55); got != "0x55" {
		t.Fatalf("expected hex, got %q", got)
	}
}

func TestParseAndWriteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "doc.tmats")
	content := "# Sample\nR-1\\CHE-1:1;\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	doc, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	digest, err := doc.ComputeDigest()
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	out := WithDigest(doc, digest)
	if !strings.Contains(out, digest) {
		t.Fatalf("output missing digest")
	}
}
