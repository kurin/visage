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
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/kurin/visage"
	"github.com/kurin/visage/web"
)

var (
	root   = flag.String("root", "", "serve the given directory")
	port   = flag.String("port", "8080", "port to listen on")
	domain = flag.String("domain", "", "domain (for TLS)")
)

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
	auth := v.NewDirGrant(fs, "/", time.Time{})
	fmt.Println(auth)
	w := web.Server{
		Visage: v,
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
