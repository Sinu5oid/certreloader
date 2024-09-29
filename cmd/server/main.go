package main

import (
	"crypto/tls"
	"flag"
	"net/http"
	"time"

	"github.com/sinu5oid/certreloader"
)

func main() {
	cert := flag.String("cert", "./cert.pem", "certificate file path")
	key := flag.String("key", "./key.pem", "key file path")
	renewal := flag.Int("renew", 60, "certificate renewal seconds")
	verbose := flag.Bool("v", false, "verbose")
	address := flag.String("address", ":443", "listen address")

	flag.Parse()

	cr, err := certreloader.NewReloader(*cert, *key)
	if err != nil {
		panic(err)
	}

	cr.WithReloadInterval(time.Duration(*renewal) * time.Second).SetVerbose(*verbose)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World"))
		w.WriteHeader(200)
	})

	srv := &http.Server{
		Addr:    *address,
		Handler: nil,
		TLSConfig: &tls.Config{
			GetCertificate: cr.GetCertificateFunc(),
		},
	}

	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
