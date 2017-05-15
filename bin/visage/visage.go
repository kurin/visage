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

// Visage is a very simple implementation of the visage library with the bad
// web UI.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/acme/autocert"

	"github.com/kurin/visage"
	"github.com/kurin/visage/oauth2/github"
	"github.com/kurin/visage/oauth2/google"
	"github.com/kurin/visage/web"
)

var (
	root   = flag.String("root", "", "serve the given directory")
	port   = flag.String("port", "8080", "port to listen on")
	domain = flag.String("domain", "", "domain (for TLS)")
	admin  = flag.String("admin", "", "admin user specification")
)

func ghcfg() *github.Config {
	id := os.Getenv("GH_CLIENT_ID")
	secret := os.Getenv("GH_CLIENT_SECRET")
	url := os.Getenv("GH_REDIRECT_URL")
	if id == "" || secret == "" || url == "" {
		return nil
	}
	return &github.Config{
		ClientID:     id,
		ClientSecret: secret,
		RedirectURI:  url,
	}
}

func gcfg() *google.Config {
	id := os.Getenv("GOOG_CLIENT_ID")
	secret := os.Getenv("GOOG_CLIENT_SECRET")
	url := os.Getenv("GOOG_REDIRECT_URL")
	if id == "" || secret == "" || url == "" {
		return nil
	}
	return &google.Config{
		ClientID:     id,
		ClientSecret: secret,
		RedirectURI:  url,
	}
}

func main() {
	flag.Parse()
	if *root == "" {
		fmt.Println("set --root")
		return
	}
	var certManager autocert.Manager
	if *domain != "" {
		certManager = autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*domain),
			Cache:      autocert.DirCache(os.TempDir()),
		}
	}
	fs := visage.Directory(*root)
	v := visage.New()
	if err := v.AddFileSystem(fs); err != nil {
		fmt.Println(err)
		return
	}
	a, err := web.ParseGrant(*admin)
	if err != nil {
		fmt.Println(err)
		return
	}
	ag, _ := a.Make()
	w := web.Server{
		Visage: v,
		GitHub: ghcfg(),
		Google: gcfg(),
		Admin:  ag,
	}
	w.RegisterHandlers("/")
	if *domain != "" {
		server := &http.Server{
			Addr: ":" + *port,
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
		}
		server.ListenAndServeTLS("", "")
		return
	}
	log.Fatal(http.ListenAndServe(":"+*port, nil))
}
