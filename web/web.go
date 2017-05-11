// Package web implements a simple web UI for visage.
//
// This package is entirely proof of concept and is insecure
// and should not be trusted with actual secrets even a
// little bit.
//
// Oh man it's so bad.
package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"time"

	"github.com/kurin/visage"
)

type Server struct {
	Visage    *visage.Share
	SecretKey string

	adminSet bool

	// This is, of course, terrible, but this is the terrible proof of concept
	// UI.  Don't persist these.
	adminUser, adminPass string
}

func (s *Server) RegisterHandlers(root string) {
	// TODO: accept a custom mux
	http.HandleFunc(path.Join("/", root, "/"), s.root)
	http.HandleFunc(path.Join("/", root, "/list"), s.list)
	http.HandleFunc(path.Join("/", root, "/settoken"), s.setToken)
	http.HandleFunc(path.Join("/", root, "/get"), s.get)
	http.HandleFunc(path.Join("/", root, "/admin"), s.admin)
	http.HandleFunc(path.Join("/", root, "/setadmin"), s.setAdmin)
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	if !s.adminSet {
		s.admin(w, r)
		return
	}
	w.Write([]byte("<html>\n"))
	w.Write([]byte(`
<form action="/settoken" method="POST">
<input type="password" name="auth">
</form>
	`))
	for _, f := range s.Visage.FileSystems() {
		w.Write([]byte(fmt.Sprintf(`<a href="/list?fs=%s">%s</a><br>`, url.QueryEscape(f), f)))
	}
	w.Write([]byte("</html>\n"))
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	if !s.adminSet {
		s.admin(w, r)
		return
	}
	cookie, err := r.Cookie("auth-token-secret")
	if err != nil {
		internalError(w, r, err)
		return
	}
	auth := cookie.Value
	fs := r.URL.Query().Get("fs")
	fsys, err := s.Visage.View(fs)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write([]byte("<html>\n"))
	list, err := fsys.List(visage.StaticToken(auth))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	for _, f := range list {
		w.Write([]byte(fmt.Sprintf(`<a href="/get?fs=%s&file=%s&auth=%s">%s</a><br>`, url.QueryEscape(fs), url.QueryEscape(f), auth, f)))
	}
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	if !s.adminSet {
		s.admin(w, r)
		return
	}
	cookie, err := r.Cookie("auth-token-secret")
	if err != nil {
		internalError(w, r, err)
		return
	}
	auth := cookie.Value
	file, err := url.QueryUnescape(r.URL.Query().Get("file"))
	if err != nil {
		internalError(w, r, err)
		return
	}
	fs, err := url.QueryUnescape(r.URL.Query().Get("fs"))
	if err != nil {
		internalError(w, r, err)
		return
	}
	fsys, err := s.Visage.View(fs)
	if err != nil {
		internalError(w, r, err)
		return
	}
	t := visage.StaticToken(auth)
	f, err := fsys.Open(t, file)
	if err != nil {
		internalError(w, r, err)
		return
	}
	defer f.Close()
	if rs, ok := f.(io.ReadSeeker); ok {
		http.ServeContent(w, r, "", time.Time{}, rs)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(file)))
	io.Copy(w, f)
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	if !s.adminSet {
		w.Write([]byte(`
<html>
<form action="/setadmin" method="POST">
Username: <input type="text" name="user"><br>
Password: <input type="password" name="pass"><br>
Key: <input type="password" name="key"><br>
<input type="submit"><br>
</html>
		`))
		return
	}
	w.Write([]byte(`
<html>
<form action="/grants/insert" method="POST">
	`))
	//for
	w.Write([]byte(`
</form>
</html>
	`))
}

func (s *Server) setToken(w http.ResponseWriter, r *http.Request) {
	auth := r.PostFormValue("auth")
	http.SetCookie(w, &http.Cookie{
		Name:  "auth-token-secret",
		Value: auth,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) setAdmin(w http.ResponseWriter, r *http.Request) {
	if s.adminSet {
		internalError(w, r, errors.New("admin creds already set"))
		return
	}
	user := r.PostFormValue("user")
	pass := r.PostFormValue("pass")
	key := r.PostFormValue("key")
	if key != s.SecretKey || key == "" {
		internalError(w, r, errors.New("invalid admin key"))
		return
	}
	s.adminSet = true
	s.adminUser = user
	s.adminPass = pass
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func internalError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "500 "+err.Error(), http.StatusInternalServerError)
}
