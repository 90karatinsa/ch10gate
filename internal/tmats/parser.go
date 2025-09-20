package tmats

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

type Document struct {
	entries  map[string]string
	order    []string
	comments []string
}

// Parse loads a TMATS document from disk.
func Parse(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc := parseString(string(data))
	return doc, nil
}

func parseString(raw string) *Document {
	doc := &Document{
		entries:  make(map[string]string),
		order:    make([]string, 0),
		comments: make([]string, 0),
	}
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			doc.comments = append(doc.comments, strings.TrimRight(line, "\r\n"))
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		parts := strings.Split(line, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			kv := strings.SplitN(part, ":", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			if key == "" {
				continue
			}
			val := strings.TrimSpace(kv[1])
			if _, ok := doc.entries[key]; !ok {
				doc.order = append(doc.order, key)
			}
			doc.entries[key] = val
		}
	}
	return doc
}

// Comments returns a copy of the comment lines present in the document.
func (d *Document) Comments() []string {
	if d == nil {
		return nil
	}
	out := make([]string, len(d.comments))
	copy(out, d.comments)
	return out
}

// AddComment appends a comment line when it does not already exist.
func (d *Document) AddComment(line string) bool {
	if d == nil {
		return false
	}
	trimmed := strings.TrimSpace(strings.TrimRight(line, "\r\n"))
	if trimmed == "" {
		return false
	}
	if !strings.HasPrefix(trimmed, "#") {
		trimmed = "# " + trimmed
	}
	for _, existing := range d.comments {
		if strings.TrimSpace(existing) == trimmed {
			return false
		}
	}
	d.comments = append(d.comments, trimmed)
	return true
}

// EnsureCommentWithTag ensures a comment containing tag exists; if not, the
// supplied text is appended as a new comment line.
func (d *Document) EnsureCommentWithTag(tag, text string) bool {
	if d == nil {
		return false
	}
	tag = strings.TrimSpace(tag)
	for _, existing := range d.comments {
		if tag != "" && strings.Contains(existing, tag) {
			return false
		}
	}
	return d.AddComment(text)
}

func (d *Document) cloneOrder() []string {
	out := make([]string, len(d.order))
	copy(out, d.order)
	return out
}

// Keys returns the ordered list of keys present in the document.
func (d *Document) Keys() []string {
	if d == nil {
		return nil
	}
	return d.cloneOrder()
}

// KeysWithPrefix returns the ordered list of keys with the specified prefix.
func (d *Document) KeysWithPrefix(prefix string) []string {
	if d == nil {
		return nil
	}
	var keys []string
	for _, k := range d.order {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys
}

// Get retrieves the value for key.
func (d *Document) Get(key string) (string, bool) {
	if d == nil {
		return "", false
	}
	val, ok := d.entries[key]
	return val, ok
}

// Set assigns value to key, returning true when the document changes.
func (d *Document) Set(key, value string) bool {
	if d == nil {
		return false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	value = strings.TrimSpace(value)
	if existing, ok := d.entries[key]; ok {
		if existing == value {
			return false
		}
		d.entries[key] = value
		return true
	}
	d.entries[key] = value
	d.order = append(d.order, key)
	return true
}

// Delete removes key from the document, returning true if removed.
func (d *Document) Delete(key string) bool {
	if d == nil {
		return false
	}
	if _, ok := d.entries[key]; !ok {
		return false
	}
	delete(d.entries, key)
	for i, k := range d.order {
		if k == key {
			d.order = append(d.order[:i], d.order[i+1:]...)
			break
		}
	}
	return true
}

// StringWithoutDigest serializes the document excluding G\SHA.
func (d *Document) StringWithoutDigest() string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range d.comments {
		if c != "" {
			b.WriteString(c)
		}
		b.WriteByte('\n')
	}
	for _, key := range d.order {
		if key == "G\\SHA" {
			continue
		}
		val, ok := d.entries[key]
		if !ok {
			continue
		}
		b.WriteString(key)
		b.WriteByte(':')
		b.WriteString(val)
		b.WriteString(";\n")
	}
	return b.String()
}

// String serializes the TMATS document.
func (d *Document) String() string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range d.comments {
		if c != "" {
			b.WriteString(c)
		}
		b.WriteByte('\n')
	}
	for _, key := range d.order {
		val, ok := d.entries[key]
		if !ok {
			continue
		}
		b.WriteString(key)
		b.WriteByte(':')
		b.WriteString(val)
		b.WriteString(";\n")
	}
	return b.String()
}

// ComputeDigest computes a SHA-256 digest of the TMATS document string.
func ComputeDigest(doc string) (string, error) {
	sum := sha256.Sum256([]byte(doc))
	return hex.EncodeToString(sum[:]), nil
}

// ComputeDigest computes a digest for the document excluding G\SHA.
func (d *Document) ComputeDigest() (string, error) {
	return ComputeDigest(d.StringWithoutDigest())
}

// WithDigest applies the digest to the document and returns the serialized form.
func WithDigest(doc *Document, digest string) string {
	if doc == nil {
		return ""
	}
	doc.Set("G\\SHA", digest)
	return doc.String()
}

var dataTypeNames = map[uint16]string{
	0x00: "TIME",
	0x08: "PCM",
	0x18: "1553",
	0x19: "1553",
	0x38: "A429",
}

// DataTypeName returns the canonical TMATS name for a Chapter 10 data type.
func DataTypeName(dt uint16) string {
	if name, ok := dataTypeNames[dt]; ok {
		return name
	}
	return fmt.Sprintf("0x%X", dt)
}

var timeFormatNames = map[uint8]string{
	0x00: "IRIG-106",
	0x04: "IEEE-1588",
}

// TimeFormatName returns a TMATS-friendly name for the secondary header time format.
func TimeFormatName(tf uint8) string {
	if name, ok := timeFormatNames[tf]; ok {
		return name
	}
	return fmt.Sprintf("0x%X", tf)
}
