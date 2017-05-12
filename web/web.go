//   Copyright 2017 Google
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

// Package web implements a simple web UI for visage.
//
// This package is entirely proof of concept and is insecure
// and should not be trusted with actual secrets even a
// little bit.
//
// Oh man it's so bad.
package web

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"

	"github.com/gorilla/securecookie"
	"github.com/kurin/visage"
	"github.com/kurin/visage/oauth2/github"
	"github.com/kurin/visage/oauth2/google"
)

var cookie *securecookie.SecureCookie

func init() {
	hashKey := securecookie.GenerateRandomKey(64)
	blockKey := securecookie.GenerateRandomKey(32)
	if hashKey == nil || blockKey == nil {
		panic("couldn't generate random key")
	}
	cookie = securecookie.New(hashKey, blockKey)
}

type Server struct {
	Visage *visage.Share

	Google *oauth2.Config
	GitHub *oauth2.Config

	SecretKey string
	Admin     visage.Grant
}

func (s *Server) RegisterHandlers(root string) {
	if s.Google != nil {
		google.RegisterHandlers(path.Join("/", root, "/google.login"), s.Google)
	}
	if s.GitHub != nil {
		github.RegisterHandlers(path.Join("/", root, "/github.login"), s.GitHub)
	}
	// TODO: accept a custom mux
	http.HandleFunc(path.Join("/", root, "/"), s.root)
	http.HandleFunc(path.Join("/", root, "/list"), s.list)
	http.HandleFunc(path.Join("/", root, "/get"), s.get)
	http.HandleFunc(path.Join("/", root, "/share"), s.share)
	http.HandleFunc(path.Join("/", root, "/setshare"), s.setShare)
}

type fs struct {
	Name string
}

type auth struct {
	Path       string
	Name       string
	Logged     bool
	Credential string
}

type rootPage struct {
	FileSystems []fs
	Auths       []auth
}

func (s *Server) rootPage(r *http.Request) rootPage {
	p := rootPage{}

	for _, f := range s.Visage.FileSystems() {
		p.FileSystems = append(p.FileSystems, fs{Name: f})
	}

	ctx := s.Context(r)

	if s.Google != nil {
		a := auth{
			Path: "/google.login",
			Name: "The Googles",
		}
		a.Credential, a.Logged = google.Show(ctx)
		p.Auths = append(p.Auths, a)
	}
	if s.GitHub != nil {
		a := auth{
			Path: "/github.login",
			Name: "GitHubris",
		}
		a.Credential, a.Logged = github.Show(ctx)
		p.Auths = append(p.Auths, a)
	}
	return p
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	p := s.rootPage(r)
	temp, err := template.ParseFiles("web/static/visage.html")
	if err != nil {
		panic(err)
	}
	if err := temp.Execute(w, p); err != nil {
		panic(err)
	}
}

func (s *Server) Context(r *http.Request) context.Context {
	ctx := r.Context()
	switch {
	case s.Google != nil:
		ctx = google.Context(ctx, r)
		fallthrough
	case s.GitHub != nil:
		ctx = github.Context(ctx, r)
		fallthrough
	default:
	}
	return ctx
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	ctx := s.Context(r)
	fs := r.URL.Query().Get("fs")
	fsys, err := s.Visage.View(fs)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write([]byte("<html>\n"))
	list, err := fsys.List(ctx)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	for _, f := range list {
		w.Write([]byte(fmt.Sprintf(`<a href="/get?fs=%s&file=%s">%s</a><br>`, url.QueryEscape(fs), url.QueryEscape(f), f)))
	}
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	ctx := s.Context(r)
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
	f, err := fsys.Open(ctx, file)
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

func (s *Server) share(w http.ResponseWriter, r *http.Request) {
	fs, err := url.QueryUnescape(r.URL.Query().Get("fs"))
	if err != nil {
		internalError(w, r, err)
		return
	}
	fsys, err := s.Visage.FileSystem(fs)
	if err != nil {
		internalError(w, r, err)
		return
	}

	w.Write([]byte("<html>"))
	w.Write([]byte(`
<form action="/setshare" method="POST">
<input type="hidden" name="fs" value="` + fs + `">
token: <input type="text" name="token"><br>
admin: <input type="text" name="user"><br>
pass: <input type="password" name="pass"><br>
<input type="submit"><br>
`))
	if err := visage.Walk(fsys, "", func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return err
		}
		t := "file"
		if fi.IsDir() {
			t = "dir"
		}
		w.Write([]byte(fmt.Sprintf(`<input type="checkbox" name="%s" value="%s">%s</input><br>`, t, path, path)))
		return nil
	}); err != nil {
		log.Print(err)
	}
	w.Write([]byte("<form>"))
	w.Write([]byte("</html>"))
}

func (s *Server) setShare(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		internalError(w, r, err)
		return
	}
	//admin := r.PostFormValue("user")
	//pass := r.PostFormValue("pass")
	//if !s.adminSet || (s.adminUser != admin && s.adminPass != pass) {
	//	internalError(w, r, errors.New("invalid admin key"))
	//	return
	//}
	//token := r.PostFormValue("token")
	fs := r.PostFormValue("fs")
	if len(r.Form["file"]) > 0 {
		g := visage.NewGrant()
		g = google.VerifyEmails(g, []string{"kurin@google.com"})
		g = visage.WithAllowFileList(g, r.Form["file"])
		g = visage.WithTimeout(g, time.Second*20)
		s.Visage.AddGrant(fs, g)
	}
	for _, d := range r.Form["dir"] {
		g := visage.NewGrant()
		g = github.VerifyLogins(g, []string{"kurin"})
		g = visage.WithAllowPrefix(g, d)
		g = visage.WithTimeout(g, time.Minute)
		s.Visage.AddGrant(fs, g)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func internalError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "500 "+err.Error(), http.StatusInternalServerError)
}

type Grant struct {
	Provider   string    `json:"provider"`
	Expires    time.Time `json:"expires"`
	Title      string    `json:"title"`
	AllowPfx   []string  `json:"allow_prefix"`
	AllowFiles []string  `json:"allow_files"`
	Values     []string  `json:"values"`
}

func (g Grant) Make() (visage.Grant, visage.CancelFunc) {
	n := visage.NewGrant()
	switch g.Provider {
	case "google":
		n = google.VerifyEmails(n, g.Values)
	case "github":
		n = github.VerifyLogins(n, g.Values)
	}
	if !g.Expires.IsZero() {
		n = visage.WithDeadline(n, g.Expires)
	}
	return visage.WithCancel(n)
}

type FileSystem struct {
	Type   string   `json:"type"`
	Grants []string `json:"grant_names"`
}
