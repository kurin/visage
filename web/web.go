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

	SecretKey string
	Admin     visage.Grant
}

func (s *Server) RegisterHandlers(root string) {
	if s.Google != nil {
		s.Google.RegisterHandlers(path.Join("/", root, "/google.login"))
	}
	if s.GitHub != nil {
		s.GitHub.RegisterHandlers(path.Join("/", root, "/github.login"))
	}
	// TODO: accept a custom mux
	http.HandleFunc(path.Join("/", root, "/"), s.root)
	http.HandleFunc(path.Join("/", root, "/list"), s.list)
	http.HandleFunc(path.Join("/", root, "/get"), s.get)
	http.HandleFunc(path.Join("/", root, "/share"), s.share)
	http.HandleFunc(path.Join("/", root, "/setshare"), s.setShare)
	http.HandleFunc(path.Join("/", root, "/fs"), s.fs)
	http.HandleFunc(path.Join("/", root, "/setfs"), s.setFS)
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
	Admin       bool
}

func servePage(w http.ResponseWriter, r *http.Request, tfile string, dot interface{}) {
	temp, err := template.ParseFiles(tfile)
	if err != nil {
		panic(err)
	}
	if err := temp.Execute(w, dot); err != nil {
		panic(err)
	}
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	ctx := s.Context(r)
	p := rootPage{}
	if s.Admin != nil {
		p.Admin = s.Admin.Verify(ctx)
	}
	for _, f := range s.Visage.FileSystems() {
		p.FileSystems = append(p.FileSystems, fs{Name: f})
	}
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
	servePage(w, r, "web/static/visage.html", p)
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

type listPage struct {
	FileSystem string
	Files      []string
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	ctx := s.Context(r)
	fs := r.URL.Query().Get("fs")
	view, err := s.Visage.View(fs)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	list, err := view.List(ctx)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p := &listPage{
		FileSystem: fs,
		Files:      list,
	}
	servePage(w, r, "web/static/list.html", p)
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

type sharePage struct {
	FS         string
	GrantTypes []string
	Files      []string
}

func (s *Server) share(w http.ResponseWriter, r *http.Request) {
	ctx := s.Context(r)
	if !s.Admin.Verify(ctx) {
		http.Error(w, "you're not an admin", http.StatusUnauthorized)
		return
	}
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

	p := sharePage{
		FS: fs,
	}
	if s.Google != nil {
		p.GrantTypes = append(p.GrantTypes, "google")
	}
	if s.GitHub != nil {
		p.GrantTypes = append(p.GrantTypes, "github")
	}
	if err := visage.Walk(fsys, "", func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			if fi != nil && fi.IsDir() {
				return filepath.SkipDir
			}
			return err
		}
		if fi.IsDir() {
			return nil
		}
		p.Files = append(p.Files, path)
		return nil
	}); err != nil {
		log.Print(err)
	}
	servePage(w, r, "web/static/share.html", p)
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
	gtype := r.PostFormValue("grant-type")
	gprinc := r.PostFormValue("grant-principal")
	gttl := r.PostFormValue("grant-ttl")
	g := visage.NewGrant()
	switch gtype {
	case "google":
		g = google.VerifyEmail(g, gprinc)
	case "github":
		g = github.VerifyLogin(g, gprinc)
	}
	ttl, err := time.ParseDuration(gttl)
	if err != nil {
		internalError(w, r, err)
		return
	}
	g = visage.WithTimeout(g, ttl)
	fs := r.PostFormValue("fs")
	if len(r.Form["files"]) > 0 {
		g = visage.WithAllowFileList(g, r.Form["files"])
	}
	s.Visage.AddGrant(fs, g)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) fs(w http.ResponseWriter, r *http.Request) {
	ctx := s.Context(r)
	if !s.Admin.Verify(ctx) {
		http.Error(w, "you're not an admin", http.StatusUnauthorized)
		return
	}
	servePage(w, r, "web/static/fs.html", nil)
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
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func internalError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "500 "+err.Error(), http.StatusInternalServerError)
}

func ParseGrant(s string) (*Grant, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	g := &Grant{}
	g.Provider = u.Scheme
	g.Values = []string{u.Host}

	for _, ent := range strings.Split(u.Path, "/") {
		if strings.Index(ent, "=") < 0 {
			continue
		}
		parts := strings.SplitN(ent, "=", 2)
		key := parts[0]
		value := parts[1]
		switch key {
		case "ttl":
			d, err := time.ParseDuration(value)
			if err != nil {
				return nil, err
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

type FileSystem struct {
	Type   string   `json:"type"`
	Grants []string `json:"grant_names"`
}
