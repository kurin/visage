// Package google provides visage grants and tokens for Google Single-Sign On.
package google

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/kurin/visage"

	"golang.org/x/oauth2"
)

const googleEndpoint = "https://www.googleapis.com/oauth2/v2/userinfo"

type ctxKey int

const oauthToken ctxKey = 0

type access struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified_email"`
}

func WithToken(ctx context.Context, token *oauth2.Token) context.Context {
	resp, err := http.Get(fmt.Sprintf("%s?access_token=%s", googleEndpoint, token.AccessToken))
	if err != nil {
		return ctx
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	acc := &access{}
	if err := dec.Decode(acc); err != nil {
		return ctx
	}
	return context.WithValue(ctx, oauthToken, acc)
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
	return g.allowed[acc.Email] || g.Grant.Verify(ctx)
}

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

type CookieWrapper interface {
	Encode(string, interface{}) (string, error)
	Decode(string, string, interface{}) error
}

type OAuthHandlers struct {
	Config        *oauth2.Config
	Cookie        CookieWrapper
	InternalError func(http.ResponseWriter, *http.Request, error)
}

const (
	tokenCookie = "goog-auth-token"
	stateCookie = "goog-oauth-state"
)

func (o *OAuthHandlers) NeedsAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(tokenCookie)
		if err != nil {
			o.Login(w, r)
			return
		}
		var tok oauth2.Token
		if err := o.Cookie.Decode(tokenCookie, c.Value, &tok); err != nil {
			o.Login(w, r)
			return
		}
		req := r.WithContext(WithToken(r.Context(), &tok))
		h(w, req)
	}
}

func (o *OAuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		o.InternalError(w, r, err)
		return
	}
	state := hex.Dump(b)
	code, err := o.Cookie.Encode(stateCookie, state)
	if err != nil {
		o.InternalError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  stateCookie,
		Value: code,
	})
	rURL := o.Config.AuthCodeURL(state)
	http.Redirect(w, r, rURL, http.StatusTemporaryRedirect)
}

func (o *OAuthHandlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(stateCookie)
	if err != nil {
		o.InternalError(w, r, err)
		return
	}
	var state string
	if err := o.Cookie.Decode(stateCookie, c.Value, &state); err != nil {
		o.InternalError(w, r, err)
		return
	}
	rState := r.FormValue("state")
	if rState != state {
		log.Print("oauth state mismatch")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	code := r.FormValue("code")
	token, err := o.Config.Exchange(oauth2.NoContext, code)
	if err != nil {
		o.InternalError(w, r, err)
		return
	}
	enc, err := o.Cookie.Encode(tokenCookie, token)
	if err != nil {
		o.InternalError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  tokenCookie,
		Value: enc,
	})
	rURI := "/" //r.FormValue("redirect_uri")
	http.Redirect(w, r, rURI, http.StatusTemporaryRedirect)
}
