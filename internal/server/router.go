package server

import "net/http"

// NewRouter wires HTTP routes to the server's handlers.
func NewRouter(s *Server) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", s.handleValidate)
	mux.HandleFunc("/auto-fix", s.handleAutoFix)
	mux.HandleFunc("/manifest", s.handleManifest)
	mux.HandleFunc("/profiles", s.handleProfiles)
	mux.HandleFunc("/upload", s.handleUpload)
	mux.HandleFunc("/openapi.yaml", s.handleOpenAPI)
	mux.HandleFunc("/artifacts/", s.handleArtifactDownload)
	if s.enableAdmin && s.updateInstaller != nil {
		mux.HandleFunc("/admin/update", s.handleAdminUpdate)
	}
	ui, err := newUIHandler()
	if err != nil {
		return nil, err
	}
	mux.Handle("/", ui)
	return mux, nil
}
