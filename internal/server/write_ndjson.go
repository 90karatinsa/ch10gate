package server

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"example.com/ch10gate/internal/rules"
)

// NDJSONWriter streams newline-delimited JSON objects to the underlying writer.
type NDJSONWriter struct {
	mu      sync.Mutex
	writer  io.Writer
	flusher http.Flusher
}

// NewNDJSONWriter wraps the provided ResponseWriter with a helper that writes
// newline-delimited JSON. If the writer supports http.Flusher, Flush will be
// invoked after every write to push bytes to the client promptly.
func NewNDJSONWriter(w http.ResponseWriter) *NDJSONWriter {
	var flusher http.Flusher
	if f, ok := w.(http.Flusher); ok {
		flusher = f
	}
	return &NDJSONWriter{writer: w, flusher: flusher}
}

// WriteDiagnostic marshals the diagnostic and writes it as a single NDJSON
// record.
func (w *NDJSONWriter) WriteDiagnostic(d rules.Diagnostic) error {
	return w.WriteObject(d)
}

// WriteObject marshals the provided value to JSON, writes it followed by a
// newline and flushes the response.
func (w *NDJSONWriter) WriteObject(v any) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := w.writer.Write(data); err != nil {
		return err
	}
	if _, err := w.writer.Write([]byte("\n")); err != nil {
		return err
	}
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return nil
}
