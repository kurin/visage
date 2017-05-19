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
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/kurin/visage"
	"github.com/kurin/visage/oauth2/github"
	"github.com/kurin/visage/oauth2/google"
)

type Server struct {
	Visage *visage.Share

	Google *google.Config
	GitHub *github.Config

	State *State
	Admin visage.Grant

	template *template.Template
}

func (s *Server) RegisterHandlers(root string) error {
	if s.Google != nil {
		s.Google.RegisterHandlers(path.Join("/", root, "/google.login"))
	}
	if s.GitHub != nil {
		s.GitHub.RegisterHandlers(path.Join("/", root, "/github.login"))
	}
	// TODO: accept a custom mux
	http.HandleFunc(path.Join("/", root, "/"), s.root)
	//http.HandleFunc(path.Join("/", root, "/list"), s.list)
	//http.HandleFunc(path.Join("/", root, "/get"), s.get)
	http.HandleFunc(path.Join("/", root, "/setfs"), s.setFS)

	temp, err := template.New("null").Funcs(template.FuncMap{
		"lower":   strings.ToLower,
		"id":      mkid,
		"isAdmin": func() bool { return false },
	}).ParseGlob("web/static/*")
	if err != nil {
		return err
	}
	s.template = temp
	s.State = &State{}
	return nil
}

func mkid(s string) string {
	s = strings.ToLower(s)
	s = strings.Replace(s, " ", "-", -1)
	s = strings.Replace(s, "/", "", -1)
	return s
}

type fs struct {
	Name  string
	ID    string
	Admin bool
}

type auth struct {
	Path       string
	Name       string
	Logged     bool
	Credential string
	Logout     string
}

type page struct {
	Admin bool
	Auths []auth
	State *State
}

func (s *Server) servePage(w http.ResponseWriter, r *http.Request, name string, dot interface{}) {
	ctx := s.Context(r)
	temp, err := s.template.Clone()
	if err != nil {
		panic(err)
	}
	temp = temp.Funcs(template.FuncMap{
		"isAdmin": func() bool { return s.Admin.Verify(ctx) },
	})
	if err := temp.ExecuteTemplate(w, name, dot); err != nil {
		panic(err)
	}
}

func (s *Server) page(r *http.Request) page {
	p := page{
		State: s.State,
	}
	ctx := s.Context(r)
	if s.Google != nil {
		a := auth{
			Path: "/google.login",
			Name: "Google",
		}
		a.Credential, a.Logged = google.Show(ctx)
		a.Logout = s.Google.LogoutPath
		p.Auths = append(p.Auths, a)
	}
	if s.GitHub != nil {
		a := auth{
			Path: "/github.login",
			Name: "GitHub",
		}
		a.Credential, a.Logged = github.Show(ctx)
		a.Logout = s.GitHub.LogoutPath
		p.Auths = append(p.Auths, a)
	}
	return p
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	p := s.page(r)
	s.servePage(w, r, "visage.html", p)
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

func (s *Server) setShare(w http.ResponseWriter, r *http.Request) {
	ctx := s.Context(r)
	if !s.Admin.Verify(ctx) {
		http.Error(w, "you're not an admin", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		internalError(w, r, err)
		return
	}
	gstr := r.PostFormValue("grant")
	gr, err := ParseGrant(gstr)
	if err != nil {
		internalError(w, r, err)
		return
	}
	g, _ := gr.Make()
	fs := r.PostFormValue("fs")
	if len(r.Form["files"]) > 0 {
		g = visage.AllowFiles(g, r.Form["files"])
	}
	s.Visage.AddGrant(fs, g)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) setFS(w http.ResponseWriter, r *http.Request) {
	ctx := s.Context(r)
	if !s.Admin.Verify(ctx) {
		http.Error(w, "you're not an admin", http.StatusUnauthorized)
		return
	}
	fs := r.PostFormValue("fs")
	fsys := visage.Directory(fs)
	if err := s.Visage.AddFileSystem(fsys); err != nil {
		internalError(w, r, err)
		return
	}
	s.State.Shares = append(s.State.Shares, Share{
		FileSystem: fs,
		Name:       fs,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func internalError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "500 "+err.Error(), http.StatusInternalServerError)
}

type State struct {
	Shares []Share `json:"shares"`
	Admins []Grant `json:"admins"`
}

type Share struct {
	FileSystem string  `json:"file_system"`
	Root       string  `json:"root"`
	Name       string  `json:"name"`
	Grants     []Grant `json:"grants"`
}

// ParseGrant parses the given string into a Grant.  s must be of the form
//     provider:principal[?key=val[&key2=val2]]
// where the principal is in the grant's Values, and various arguments
// can be passed via keys.
//
// The only key currently supported is ttl, which sets an expiration time.
func ParseGrant(s string) (Grant, error) {
	u, err := url.Parse(s)
	if err != nil {
		return Grant{}, err
	}

	g := Grant{}
	g.Provider = u.Scheme
	g.Values = []string{u.Opaque}

	for key := range u.Query() {
		val := u.Query().Get(key)
		switch key {
		case "ttl":
			d, err := time.ParseDuration(val)
			if err != nil {
				return Grant{}, err
			}
			g.Expires = time.Now().Add(d)
		}
	}
	return g, nil
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
		n = google.VerifyEmail(n, g.Values...)
	case "github":
		n = github.VerifyLogin(n, g.Values...)
	}
	if !g.Expires.IsZero() {
		n = visage.WithDeadline(n, g.Expires)
	}
	return visage.WithCancel(n)
}
