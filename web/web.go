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
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/gorilla/securecookie"
	"github.com/kurin/visage"
	goog "github.com/kurin/visage/oauth2/google"
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

type AuthType int

const (
	AuthToken AuthType = iota
	AuthGoogle
)

type Server struct {
	Visage    *visage.Share
	SecretKey string
	Auth      AuthType

	GoogleHandlers *goog.OAuthHandlers

	adminSet bool

	// This is, of course, terrible, but this is the terrible proof of concept
	// UI.  Don't persist these.
	adminUser, adminPass string
}

func (s *Server) RegisterHandlers(root string) {
	s.adminSet = true
	s.Auth = AuthGoogle
	cfg, err := ioutil.ReadFile("/home/kurin/json.oauth2")
	if err != nil {
		panic(err)
	}
	c, err := google.ConfigFromJSON(cfg, "email")
	if err != nil {
		panic(err)
	}
	s.GoogleHandlers = &goog.OAuthHandlers{
		Config:        c,
		Cookie:        cookie,
		InternalError: internalError,
	}
	// TODO: accept a custom mux
	http.HandleFunc(path.Join("/", root, "/"), s.needAuth(s.root))
	http.HandleFunc(path.Join("/", root, "/list"), s.needAuth(s.list))
	http.HandleFunc(path.Join("/", root, "/get"), s.needAuth(s.get))
	http.HandleFunc(path.Join("/", root, "/admin"), s.admin)
	http.HandleFunc(path.Join("/", root, "/setadmin"), s.setAdmin)
	http.HandleFunc(path.Join("/", root, "/share"), s.share)
	http.HandleFunc(path.Join("/", root, "/setshare"), s.setShare)
	// oauth
	http.HandleFunc(path.Join("/", root, "/login"), s.login)
}

func (s *Server) needAuth(f http.HandlerFunc) http.HandlerFunc {
	if !s.adminSet {
		return func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		}
	}
	switch s.Auth {
	case AuthGoogle:
		return s.GoogleHandlers.NeedsAuth(f)
	default:
		return f
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	switch s.Auth {
	case AuthGoogle:
		s.GoogleHandlers.LoginHandler(w, r)
	default:
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<html>\n"))
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
	ctx := r.Context()
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
		g = goog.VerifyEmails(g, []string{"kurin@google.com"})
		g = visage.WithAllowFileList(g, r.Form["file"])
		g = visage.WithTimeout(g, time.Minute*5)
		s.Visage.AddGrant(fs, g)
		fmt.Println("added file grants")
	}
	for _, d := range r.Form["dir"] {
		fmt.Println("added dir grant", d)
		g := visage.NewGrant()
		g = visage.WithAllowPrefix(g, d)
		g = visage.WithTimeout(g, time.Minute)
		s.Visage.AddGrant(fs, g)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func internalError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "500 "+err.Error(), http.StatusInternalServerError)
}
