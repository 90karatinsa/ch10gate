package server

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		http.Error(w, fmt.Sprintf("parse multipart: %v", err), http.StatusBadRequest)
		return
	}
	if r.MultipartForm == nil {
		http.Error(w, "no files provided", http.StatusBadRequest)
		return
	}
	var refs []ArtifactRef
	for _, files := range r.MultipartForm.File {
		for _, fh := range files {
			ref, err := s.saveUploadedFile(fh)
			if err != nil {
				http.Error(w, fmt.Sprintf("save upload %s: %v", fh.Filename, err), http.StatusBadRequest)
				return
			}
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		http.Error(w, "no files uploaded", http.StatusBadRequest)
		return
	}
	resp := struct {
		Files []ArtifactRef `json:"files"`
	}{Files: refs}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) saveUploadedFile(fh *multipart.FileHeader) (ArtifactRef, error) {
	if fh == nil {
		return ArtifactRef{}, fmt.Errorf("nil file header")
	}
	src, err := fh.Open()
	if err != nil {
		return ArtifactRef{}, err
	}
	defer src.Close()
	ext := filepath.Ext(fh.Filename)
	pattern := "upload-*"
	if ext != "" {
		pattern = fmt.Sprintf("upload-*%s", ext)
	}
	dest, err := os.CreateTemp(s.uploadsDir, pattern)
	if err != nil {
		return ArtifactRef{}, err
	}
	if _, err := io.Copy(dest, src); err != nil {
		dest.Close()
		os.Remove(dest.Name())
		return ArtifactRef{}, err
	}
	dest.Close()
	art, err := s.addArtifact(dest.Name(), fh.Filename, guessContentType(fh.Filename), "upload")
	if err != nil {
		return ArtifactRef{}, err
	}
	return toRef(art), nil
}
