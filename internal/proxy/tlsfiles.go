package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// CertFiles serves a TLS certificate from a cert/key pair of files and re-reads them when either
// changes (cert-manager rotation). A pair that fails to load, doesn't match, or is expired
// leaves the previous certificate in use, with a warning.
type CertFiles struct {
	r *reloadable[*tls.Certificate]
}

// LoadCertFiles loads and validates the pair: it must parse, the certificate must match the
// key, and the certificate must be valid now. now is time.Now unless a test says otherwise.
func LoadCertFiles(certPath, keyPath string, log *slog.Logger, now func() time.Time) (*CertFiles, error) {
	if now == nil {
		now = time.Now
	}
	load := func() (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(certPath, keyPath) // also checks that the key matches
		if err != nil {
			return nil, fmt.Errorf("tls pair: %w", err)
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("tls certificate: %w", err)
		}
		c.Leaf = leaf
		switch t := now(); {
		case t.After(leaf.NotAfter):
			return nil, fmt.Errorf("tls certificate expired on %s", leaf.NotAfter.UTC().Format(time.DateOnly))
		case t.Before(leaf.NotBefore):
			return nil, fmt.Errorf("tls certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.DateOnly))
		}
		return &c, nil
	}
	r, err := newReloadable([]string{certPath, keyPath}, load, func(err error) {
		log.Warn("tls files changed but did not load; keeping the previous certificate", "err", err)
	})
	if err != nil {
		return nil, err
	}
	return &CertFiles{r: r}, nil
}

// GetCertificate is a tls.Config.GetCertificate.
func (c *CertFiles) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := c.r.get()
	if cert == nil {
		return nil, errors.New("no certificate")
	}
	return cert, nil
}

// NotAfter is the expiry of the certificate currently in use.
func (c *CertFiles) NotAfter() time.Time { return c.r.get().Leaf.NotAfter }

// LeafDER is the DER encoding of the leaf certificate currently in use.
func (c *CertFiles) LeafDER() []byte { return c.r.get().Certificate[0] }
