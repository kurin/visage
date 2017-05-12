// Package github provides visage grants and tokens for GitHub authentication.
package github

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/securecookie"
	"github.com/kurin/visage"

	"golang.org/x/oauth2"
)

var sc *securecookie.SecureCookie

func init() {
	hashKey := securecookie.GenerateRandomKey(64)
	blockKey := securecookie.GenerateRandomKey(32)
	if hashKey == nil || blockKey == nil {
		panic("couldn't generate random key")
	}
	sc = securecookie.New(hashKey, blockKey)
}

type ctxKey int

const oauthToken ctxKey = 0

const githubEndpoint = "https://api.github.com/user"

type access struct {
	Login string `json:"login"`
}

type grant struct {
	visage.Grant

	allowed map[string]bool
}

func (g *grant) Valid() bool             { return g.Grant.Valid() }
func (g *grant) Allows(path string) bool { return g.Grant.Allows(path) }

func (g *grant) Verify(ctx context.Context) bool {
	acc, ok := ctx.Value(oauthToken).(*access)
	if !ok {
		return false
	}
	return g.allowed[acc.Login] || g.Grant.Verify(ctx)
}

// VerifyLogins returns a grant that will verify users by their GitHub login.
func VerifyLogins(g visage.Grant, logins []string) visage.Grant {
	n := &grant{
		Grant:   g,
		allowed: make(map[string]bool),
	}
	for _, l := range logins {
		n.allowed[l] = true
	}
	return n
}

// RegisterHandlers registers GitHub authentication handlers.  The given path
// is the landing URL to begin the sign-in flow, and the return handler
// is registered at the URL listed in the config.
func RegisterHandlers(path string, config *oauth2.Config) error {
	http.HandleFunc(path, loginHandler(config))
	r, err := url.Parse(config.RedirectURL)
	if err != nil {
		return err
	}
	http.HandleFunc(r.Path, loginReturnHandler(config))
	return nil
}

const (
	tokenCookie = "github-auth-token"
	stateCookie = "github-oauth-state"
)

// Context returns a context that is updated with a GitHub authentication
// token from the given HTTP request, if it exists.
func Context(ctx context.Context, r *http.Request) context.Context {
	if _, ok := ctx.Value(oauthToken).(*access); ok {
		return ctx
	}
	c, err := r.Cookie(tokenCookie)
	if err != nil {
		return ctx
	}
	var tok oauth2.Token
	if err := sc.Decode(tokenCookie, c.Value, &tok); err != nil {
		return ctx
	}
	resp, err := http.Get(fmt.Sprintf("%s?access_token=%s", githubEndpoint, tok.AccessToken))
	if err != nil {
		return ctx
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	acc := &access{}
	if err := dec.Decode(acc); err != nil {
		return ctx
	}
	if acc.Login == "" {
		return ctx
	}
	return context.WithValue(ctx, oauthToken, acc)
}

func loginHandler(config *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		state := fmt.Sprintf("%x", sha1.Sum(b))
		code, err := sc.Encode(stateCookie, state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:  stateCookie,
			Value: code,
		})
		rURL := config.AuthCodeURL(state)
		http.Redirect(w, r, rURL, http.StatusTemporaryRedirect)
	}
}

func loginReturnHandler(config *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(stateCookie)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var state string
		if err := sc.Decode(stateCookie, c.Value, &state); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rState := r.FormValue("state")
		if rState != state {
			http.Error(w, "oauth2 state mismatch", http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		token, err := config.Exchange(oauth2.NoContext, code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		enc, err := sc.Encode(tokenCookie, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:  tokenCookie,
			Value: enc,
		})
		rURI := r.FormValue("redirect_uri")
		if rURI == "" {
			rURI = "/"
		}
		http.Redirect(w, r, rURI, http.StatusTemporaryRedirect)
	}
}

// Show reports the value of the verified credentials, if any.
func Show(ctx context.Context) (string, bool) {
	acc, ok := ctx.Value(oauthToken).(*access)
	if !ok {
		return "", ok
	}
	return acc.Login, true
}
