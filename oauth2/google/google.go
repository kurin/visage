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

// Package google provides visage grants and tokens for Google Single-Sign On.
package google

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
	"golang.org/x/oauth2/google"
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

const googleEndpoint = "https://www.googleapis.com/oauth2/v2/userinfo"

type ctxKey int

const oauthToken ctxKey = 0

type access struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified_email"`
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
	return (g.allowed[acc.Email] && acc.Verified) || g.Grant.Verify(ctx)
}

// VerifyEmails returns a grant that will verify users whose Google account is
// tied to the address listed.
func VerifyEmails(g visage.Grant, emails []string) visage.Grant {
	n := &grant{
		Grant:   g,
		allowed: make(map[string]bool),
	}
	for _, mail := range emails {
		n.allowed[mail] = true
	}
	return n
}

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// RegisterHandlers registers Google Sign-In handlers.  The given path
// is the landing URL to begin the sign-in flow, and the return handler
// is registered at the URL listed in the config.
func (c *Config) RegisterHandlers(path string) error {
	cfg := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{"email"},
		RedirectURL:  c.RedirectURI,
	}
	http.HandleFunc(path, loginHandler(cfg))
	r, err := url.Parse(c.RedirectURI)
	if err != nil {
		return err
	}
	http.HandleFunc(r.Path, loginReturnHandler(cfg))
	return nil
}

const (
	tokenCookie = "goog-auth-token"
	stateCookie = "goog-oauth-state"
)

// Context returns a context that is updated with a Google Sign-In
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
	resp, err := http.Get(fmt.Sprintf("%s?access_token=%s", googleEndpoint, tok.AccessToken))
	if err != nil {
		return ctx
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	acc := &access{}
	if err := dec.Decode(acc); err != nil {
		return ctx
	}
	if acc.Email == "" {
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
	return acc.Email, true
}
