// Package certreloader provides a convenient autoload of renewed certificates from certbot.
//
// Typically, certbot executes renew command near the 30-day expiration period twice a day,
// but since go tls.Certificate is evaluated on startup only, the certificate becomes stale and out-of sync.
// This package ensures that the files, containing SSL/TLS cert and key, are parsed on each reload interval in a
// thread-safe way
package certreloader

import (
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"
)

const logPrefix = "certreloader"

// defaultReloadInterval is 24 hours, a reasonable caching period, assuming certbot reloads certs at least twice a day
const defaultReloadInterval = time.Hour * 24

// A Reloader holds tls.Certificate with inner cert reload function implementation.
// It is assumed that certFile and keyFile last for entire process lifetime and won't produce a file reading error.
type Reloader struct {
	m              *sync.RWMutex
	cert           *tls.Certificate
	lastCertReload time.Time
	reloadInterval time.Duration

	certFile string
	keyFile  string

	verbose bool
}

// NewReloader creates new Reloader struct with provided certFile, keyFile locations.
func NewReloader(certFile string, keyFile string) (*Reloader, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("could not load keypair: %w", err)
	}

	return &Reloader{
		m:              &sync.RWMutex{},
		cert:           &cert,
		lastCertReload: time.Now(),
		reloadInterval: defaultReloadInterval,
		certFile:       certFile,
		keyFile:        keyFile,
		verbose:        false,
	}, nil
}

// WithReloadInterval sets minimal reload interval for checking new certificate.
func (r *Reloader) WithReloadInterval(duration time.Duration) *Reloader {
	r.m.Lock()
	defer r.m.Unlock()

	r.logf("set reload interval to %v", duration)

	r.reloadInterval = duration
	return r
}

// SetVerbose enables verbose logging for debugging purposes
func (r *Reloader) SetVerbose(verbose bool) *Reloader {
	r.verbose = verbose
	return r
}

// GetCertificateFunc wraps an implementations for [tls.TLSConfig] GetCertificate function.
// Reloads the certificate if needed before returning.
// Fails if reload function returns an error.
//
// The function is thread-safe
func (r *Reloader) GetCertificateFunc(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if r.shouldReload() {
		r.logf("should reload certificate, load new tls.Certificate now")

		err := r.reload()
		if err != nil {
			r.logf("could not reload certificate: %v", err)
		}
	}

	r.m.RLock()
	defer r.m.RUnlock()
	return r.cert, nil
}

// shouldReload returns if the stored (cached) certificate should be reevaluated.
func (r *Reloader) shouldReload() bool {
	r.m.RLock()
	defer r.m.RUnlock()

	return time.Now().After(r.lastCertReload.Add(r.reloadInterval))
}

// reload reevaluates the certificate by certFile / keyFile pair. Returns error if file read or tls.Certificate
// construct failed.
func (r *Reloader) reload() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("could not load keypair: %w", err)
	}

	r.m.Lock()
	defer r.m.Unlock()
	r.cert = &cert
	r.lastCertReload = time.Now()
	r.logf("certificate reloaded at %s", r.lastCertReload)
	return nil
}

func (r *Reloader) logf(format string, v ...interface{}) {
	if !r.verbose {
		return
	}

	log.Printf(fmt.Sprintf("%s %s", logPrefix, format), v...)
}
