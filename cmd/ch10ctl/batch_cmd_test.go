package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"example.com/ch10gate/internal/ch10"
	"example.com/ch10gate/internal/rules"
)

func writeSyntheticChapter10(t *testing.T, path string) {
	t.Helper()
	pkt, err := ch10.BuildTimePacket("106-15", 1, 0x00, 1_000_000)
	if err != nil {
		t.Fatalf("BuildTimePacket: %v", err)
	}
	if err := os.WriteFile(path, pkt, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestBatchCmdGeneratesOutputs(t *testing.T) {
	root := t.TempDir()
	inputDir := filepath.Join(root, "inputs")
	if err := os.MkdirAll(inputDir, 0o755); err != nil {
		t.Fatalf("MkdirAll inputs: %v", err)
	}
	tmatsDir := filepath.Join(root, "tmats")
	if err := os.MkdirAll(tmatsDir, 0o755); err != nil {
		t.Fatalf("MkdirAll tmats: %v", err)
	}
	outDir := filepath.Join(root, "out")

	dictJSON := []byte(`{"a429": [], "mil1553": []}`)

	alphaCh10 := filepath.Join(inputDir, "alpha.ch10")
	writeSyntheticChapter10(t, alphaCh10)
	if err := os.WriteFile(filepath.Join(inputDir, "alpha_dict.json"), dictJSON, 0o644); err != nil {
		t.Fatalf("WriteFile alpha dict: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "alpha.tmats"), []byte("G\\DICT:alpha_dict.json;\n"), 0o644); err != nil {
		t.Fatalf("WriteFile alpha tmats: %v", err)
	}

	nestedDir := filepath.Join(inputDir, "nested")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatalf("MkdirAll nested: %v", err)
	}
	betaCh10 := filepath.Join(nestedDir, "beta.ch10")
	writeSyntheticChapter10(t, betaCh10)
	if err := os.WriteFile(filepath.Join(tmatsDir, "beta_dict.json"), dictJSON, 0o644); err != nil {
		t.Fatalf("WriteFile beta dict: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmatsDir, "beta.tmats"), []byte("G\\DICT:beta_dict.json;\n"), 0o644); err != nil {
		t.Fatalf("WriteFile beta tmats: %v", err)
	}

	rulesPath := filepath.Join("..", "..", "profiles", "106-15", "rules.json")

	batchCmd([]string{
		"--in", inputDir,
		"--profile", "106-15",
		"--rules", rulesPath,
		"--tmats-dir", tmatsDir,
		"--out-dir", outDir,
	})

	check := func(name string) {
		out := filepath.Join(outDir, name)
		if info, err := os.Stat(out); err != nil || !info.IsDir() {
			t.Fatalf("Output dir missing for %s: %v", name, err)
		}
		diagPath := filepath.Join(out, "diagnostics.jsonl")
		if _, err := os.Stat(diagPath); err != nil {
			t.Fatalf("ReadFile diagnostics %s: %v", name, err)
		}
		accPath := filepath.Join(out, "acceptance.json")
		data, err := os.ReadFile(accPath)
		if err != nil {
			t.Fatalf("ReadFile acceptance %s: %v", name, err)
		}
		var rep rules.AcceptanceReport
		if err := json.Unmarshal(data, &rep); err != nil {
			t.Fatalf("Unmarshal acceptance %s: %v", name, err)
		}
		if !rep.Summary.Pass || rep.Summary.Errors != 0 {
			t.Fatalf("unexpected acceptance summary for %s: %+v", name, rep.Summary)
		}
	}

	check("alpha")
	check("beta")
}
