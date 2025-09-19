package rules

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteDiagnosticsNDJSONIncludesTimestamp(t *testing.T) {
	eng := &Engine{}
	withTs := int64(123456)
	eng.diagnostics = []Diagnostic{
		{
			Ts:          time.Unix(0, 0),
			File:        "input.ch10",
			RuleId:      "RP-TEST-1",
			Severity:    INFO,
			Message:     "with timestamp",
			Refs:        []string{"ref"},
			TimestampUs: &withTs,
		},
		{
			Ts:       time.Unix(1, 0),
			File:     "input.ch10",
			RuleId:   "RP-TEST-2",
			Severity: INFO,
			Message:  "without timestamp",
			Refs:     []string{"ref"},
		},
	}

	outPath := filepath.Join(t.TempDir(), "diagnostics.jsonl")
	if err := eng.WriteDiagnosticsNDJSON(outPath); err != nil {
		t.Fatalf("WriteDiagnosticsNDJSON failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	lines := bytesTrimSplit(data)
	if len(lines) != 2 {
		t.Fatalf("expected 2 diagnostics, got %d", len(lines))
	}

	var first map[string]any
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatalf("unmarshal first line failed: %v", err)
	}
	if v, ok := first["timestamp_us"]; !ok {
		t.Fatalf("timestamp_us missing from first diagnostic")
	} else if num, ok := v.(float64); !ok || int64(num) != withTs {
		t.Fatalf("timestamp_us = %v, want %d", v, withTs)
	}

	var second map[string]any
	if err := json.Unmarshal(lines[1], &second); err != nil {
		t.Fatalf("unmarshal second line failed: %v", err)
	}
	if v, ok := second["timestamp_us"]; !ok {
		t.Fatalf("timestamp_us missing from second diagnostic")
	} else if v != nil {
		t.Fatalf("timestamp_us expected nil, got %v", v)
	}
}

func bytesTrimSplit(in []byte) [][]byte {
	in = bytes.TrimSpace(in)
	if len(in) == 0 {
		return nil
	}
	parts := bytes.Split(in, []byte{'\n'})
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		p = bytes.TrimSpace(p)
		if len(p) == 0 {
			continue
		}
		cp := make([]byte, len(p))
		copy(cp, p)
		out = append(out, cp)
	}
	return out
}
