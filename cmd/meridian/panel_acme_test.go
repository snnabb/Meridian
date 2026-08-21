package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPanelACMETokenEncryptionRoundTripAndIsolation(t *testing.T) {
	secret := bytes.Repeat([]byte("a"), 32)
	otherSecret := bytes.Repeat([]byte("b"), 32)
	token := "cloudflare-token-for-automatic-renewal"
	ciphertext, err := encryptPanelACMETokenWithSecret(token, secret)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decryptPanelACMETokenWithSecret(ciphertext, secret)
	if err != nil || plain != token {
		t.Fatalf("round trip = %q, %v", plain, err)
	}
	if _, err := decryptPanelACMETokenWithSecret(ciphertext, otherSecret); err == nil {
		t.Fatal("ciphertext decrypted with a different JWT secret")
	}
	tampered := ciphertext[:len(ciphertext)-1] + "A"
	if _, err := decryptPanelACMETokenWithSecret(tampered, secret); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestCertificateRenewalWindow(t *testing.T) {
	base := panelCertificateStatus{Configured: true, CertificateCurrent: true, CertificateValid: true}
	base.DaysRemaining = 31
	if certificateNeedsRenewal(base) || !certificateCanBeReused(base) {
		t.Fatal("certificate with 31 days remaining should be reused")
	}
	base.DaysRemaining = 30
	if !certificateNeedsRenewal(base) || certificateCanBeReused(base) {
		t.Fatal("certificate with 30 days remaining should be renewed")
	}
	base.CertificateValid = false
	base.DaysRemaining = 90
	if !certificateNeedsRenewal(base) {
		t.Fatal("expired certificate should be renewed regardless of days remaining")
	}
}

func TestDisableExpiredPanelTLSIfNeeded(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "meridian.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.BootstrapPanelSettings("panel.example.com", "example.com", true, 9090); err != nil {
		t.Fatal(err)
	}

	tlsDir := t.TempDir()
	certFile := filepath.Join(tlsDir, "fullchain.pem")
	keyFile := filepath.Join(tlsDir, "privkey.pem")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "*.example.com"},
		DNSNames:     []string{"*.example.com"},
		NotBefore:    now.Add(-48 * time.Hour),
		NotAfter:     now.Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "*.example.com"},
		DNSNames:     []string{"*.example.com"},
		NotBefore:    now.Add(-48 * time.Hour),
		NotAfter:     now.Add(-time.Hour),
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(tlsDir, "enabled")
	if err := os.WriteFile(marker, []byte("enabled\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	manager := &panelCertificateManager{certFile: certFile, keyFile: keyFile, accountDir: tlsDir}
	disabled, err := disableExpiredPanelTLSIfNeeded(db, manager)
	if err != nil {
		t.Fatal(err)
	}
	if !disabled {
		t.Fatal("expired certificate was not disabled")
	}
	settings, err := db.PanelSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.TLSEnabled {
		t.Fatal("TLS remained enabled after certificate expiry")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("TLS marker still exists: %v", err)
	}
	if _, err := os.Stat(certFile); err != nil {
		t.Fatalf("certificate files should be preserved: %v", err)
	}
}

func TestLoadOrCreateACMEAccountKeyStaysWithinAccountDirectory(t *testing.T) {
	directory := t.TempDir()
	first, err := loadOrCreateACMEAccountKey(directory, "acme-account.pem")
	if err != nil {
		t.Fatalf("create account key: %v", err)
	}
	second, err := loadOrCreateACMEAccountKey(directory, "acme-account.pem")
	if err != nil {
		t.Fatalf("reload account key: %v", err)
	}
	firstPublic, err := x509.MarshalPKIXPublicKey(first.Public())
	if err != nil {
		t.Fatalf("marshal first public key: %v", err)
	}
	secondPublic, err := x509.MarshalPKIXPublicKey(second.Public())
	if err != nil {
		t.Fatalf("marshal second public key: %v", err)
	}
	if string(firstPublic) != string(secondPublic) {
		t.Fatal("reloaded account key does not match the created key")
	}
	if _, err := os.Stat(filepath.Join(directory, "acme-account.pem")); err != nil {
		t.Fatalf("account key file: %v", err)
	}

	if _, err := loadOrCreateACMEAccountKey(directory, "../escape.pem"); err == nil || err.Error() != "ACME account key filename must be a base name" {
		t.Fatalf("directory escape error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(directory), "escape.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("escape path was created: %v", err)
	}
}
