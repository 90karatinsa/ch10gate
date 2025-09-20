package common

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PatchEntry captures a single in-place modification to a Chapter 10 recording.
type PatchEntry struct {
	RuleID    string    `json:"ruleId"`
	Ref       string    `json:"ref,omitempty"`
	Offset    int64     `json:"offset,omitempty"`
	Range     string    `json:"range,omitempty"`
	BeforeHex string    `json:"beforeHex"`
	AfterHex  string    `json:"afterHex"`
	Ts        time.Time `json:"ts"`
}

// BeforeBytes decodes the hexadecimal representation of the bytes present before
// the auto-fix was applied.
func (p PatchEntry) BeforeBytes() ([]byte, error) {
	if strings.TrimSpace(p.BeforeHex) == "" {
		return nil, nil
	}
	return hex.DecodeString(p.BeforeHex)
}

// AfterBytes decodes the hexadecimal representation of the bytes written by the
// auto-fix.
func (p PatchEntry) AfterBytes() ([]byte, error) {
	if strings.TrimSpace(p.AfterHex) == "" {
		return nil, nil
	}
	return hex.DecodeString(p.AfterHex)
}

// PatchLog provides append-only access to a JSONL audit log.
type PatchLog struct {
	path string
	mu   sync.Mutex
}

// NewPatchLog returns a PatchLog that writes to the provided path.
func NewPatchLog(path string) *PatchLog {
	return &PatchLog{path: path}
}

// Path returns the backing file path for the log.
func (p *PatchLog) Path() string {
	if p == nil {
		return ""
	}
	return p.path
}

// Append writes a new entry to the audit log. Entries are serialized as
// JSON objects, one per line, to make downstream consumption and replay
// straightforward.
func (p *PatchLog) Append(entry PatchEntry) error {
	if p == nil {
		return errors.New("nil patch log")
	}
	if entry.RuleID == "" {
		return errors.New("patch entry missing ruleId")
	}
	if entry.Ts.IsZero() {
		entry.Ts = time.Now().UTC()
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := os.OpenFile(p.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// ReadPatchLog loads every entry from the supplied JSONL file.
func ReadPatchLog(path string) ([]PatchEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var entries []PatchEntry
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry PatchEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("decode patch entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}
