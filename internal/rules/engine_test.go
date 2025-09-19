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
	eng := NewEngine(RulePack{})
	withTs := int64(123456)
	src := "secondary_header"
	eng.diagnostics = []Diagnostic{
		{
			Ts:              time.Unix(0, 0),
			File:            "input.ch10",
			RuleId:          "RP-TEST-1",
			Severity:        INFO,
			Message:         "with timestamp",
			Refs:            []string{"ref"},
			TimestampUs:     &withTs,
			TimestampSource: &src,
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
	if v, ok := first["timestamp_source"]; !ok {
		t.Fatalf("timestamp_source missing from first diagnostic")
	} else if str, ok := v.(string); !ok || str != src {
		t.Fatalf("timestamp_source = %v, want %s", v, src)
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
	if v, ok := second["timestamp_source"]; !ok {
		t.Fatalf("timestamp_source missing from second diagnostic")
	} else if v != nil {
		t.Fatalf("timestamp_source expected nil, got %v", v)
	}
}

func TestWriteDiagnosticsNDJSONOmitsTimestampWhenDisabled(t *testing.T) {
	eng := NewEngine(RulePack{})
	ts := int64(42)
	src := "secondary_header"
	eng.diagnostics = []Diagnostic{
		{
			Ts:              time.Unix(0, 0),
			File:            "input.ch10",
			RuleId:          "RP-TEST-3",
			Severity:        WARN,
			Message:         "timestamp disabled",
			Refs:            []string{"ref"},
			TimestampUs:     &ts,
			TimestampSource: &src,
		},
	}
	eng.SetConfigValue("diag.include_timestamps", false)

	outPath := filepath.Join(t.TempDir(), "diagnostics.jsonl")
	if err := eng.WriteDiagnosticsNDJSON(outPath); err != nil {
		t.Fatalf("WriteDiagnosticsNDJSON failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	lines := bytesTrimSplit(data)
	if len(lines) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(lines))
	}
	var obj map[string]any
	if err := json.Unmarshal(lines[0], &obj); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if _, ok := obj["timestamp_us"]; ok {
		t.Fatalf("timestamp_us present when disabled: %v", obj["timestamp_us"])
	}
	if _, ok := obj["timestamp_source"]; ok {
		t.Fatalf("timestamp_source present when disabled: %v", obj["timestamp_source"])
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
