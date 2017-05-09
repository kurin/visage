// Package web implements a simple web UI for visage.
package web

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"path/filepath"

	"github.com/kurin/visage"
)

type Server struct {
	Visage *visage.Server
}

func (s *Server) RegisterHandlers(root string) {
	// TODO: accept a custom mux
	http.HandleFunc(path.Join("/", root, "/"), s.root)
	http.HandleFunc(path.Join("/", root, "/list"), s.list)
	http.HandleFunc(path.Join("/", root, "/get"), s.get)
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`
<html>
<form action="/list" method="GET">
<input type="text" name="auth">
<input type="submit">
</form>
</html>
	`))
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	auth := r.URL.Query().Get("auth")
	g := s.Visage.Lookup(auth)
	if g == nil {
		http.NotFound(w, r)
		return
	}
	w.Write([]byte("<html>\n"))
	for _, f := range g.List() {
		w.Write([]byte(fmt.Sprintf(`<a href="/get?file=%s&auth=%s">%s</a><br>`, url.QueryEscape(f), auth, f)))
	}
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	auth := r.URL.Query().Get("auth")
	file, err := url.QueryUnescape(r.URL.Query().Get("file"))
	if err != nil {
		internalError(w, r, err)
		return
	}
	g := s.Visage.Lookup(auth)
	f, err := g.Open(file)
	if err != nil {
		internalError(w, r, err)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(file)))
	io.Copy(w, f)
}

func internalError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "500 "+err.Error(), http.StatusInternalServerError)
}
