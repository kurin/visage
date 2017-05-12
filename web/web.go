// Package web implements a simple web UI for visage.
//
// This package is entirely proof of concept and is insecure
// and should not be trusted with actual secrets even a
// little bit.
//
// Oh man it's so bad.
package web

import (
	"fmt"
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
	Visage    *visage.Share
	SecretKey string

	Google *oauth2.Config
	GitHub *oauth2.Config

	adminSet bool

	// This is, of course, terrible, but this is the terrible proof of concept
	// UI.  Don't persist these.
	adminUser, adminPass string
}

func (s *Server) RegisterHandlers(root string) {
	s.adminSet = true
	if s.Google != nil {
		google.RegisterHandlers(path.Join("/", root, "/goog"), s.Google)
	}
	if s.GitHub != nil {
		github.RegisterHandlers(path.Join("/", root, "/gh"), s.GitHub)
	}
	// TODO: accept a custom mux
	http.HandleFunc(path.Join("/", root, "/"), s.root)
	http.HandleFunc(path.Join("/", root, "/list"), s.list)
	http.HandleFunc(path.Join("/", root, "/get"), s.get)
	http.HandleFunc(path.Join("/", root, "/share"), s.share)
	http.HandleFunc(path.Join("/", root, "/setshare"), s.setShare)
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = google.Context(ctx, r)
	ctx = github.Context(ctx, r)
	w.Write([]byte("<html>\n"))
	if s.Google != nil && !google.HasAccess(ctx) {
		w.Write([]byte(`<a href="/goog">google auth</a><br>`))
	}
	if s.GitHub != nil && !github.HasAccess(ctx) {
		w.Write([]byte(`<a href="/gh">github auth</a><br>`))
	}
	w.Write([]byte(`
<form action="/settoken" method="POST">
<input type="password" name="auth">
</form>
	`))
	for _, f := range s.Visage.FileSystems() {
		w.Write([]byte(fmt.Sprintf(`<a href="/list?fs=%s">browse %s</a>  `, url.QueryEscape(f), f)))
		w.Write([]byte(fmt.Sprintf(`<a href="/share?fs=%s">share %s</a><br>`, url.QueryEscape(f), f)))
	}
	w.Write([]byte("</html>\n"))
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = google.Context(ctx, r)
	ctx = github.Context(ctx, r)
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
	ctx := r.Context()
	ctx = google.Context(ctx, r)
	ctx = github.Context(ctx, r)
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
