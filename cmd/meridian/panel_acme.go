package main

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/publicsuffix"
)

const (
	letsEncryptProductionDirectory   = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStagingDirectory      = "https://acme-staging-v02.api.letsencrypt.org/directory"
	panelCertificateRenewalWindow    = 30 * 24 * time.Hour
	panelCertificateRenewalInterval  = 12 * time.Hour
	panelACMETokenCipherPrefix       = "v2:"
	panelACMETokenLegacyCipherPrefix = "v1:"
)

var errCertificateIssuanceBusy = errors.New("a certificate request is already running")

type panelCertificateStatus struct {
	Available                 bool   `json:"available"`
	TLSEnabled                bool   `json:"tls_enabled"`
	PanelDomain               string `json:"panel_domain"`
	PanelPrefix               string `json:"panel_prefix"`
	RouteDomain               string `json:"route_domain"`
	WildcardDomain            string `json:"wildcard_domain"`
	CertificateWildcardDomain string `json:"certificate_wildcard_domain,omitempty"`
	CertificateCurrent        bool   `json:"certificate_current"`
	CertificateValid          bool   `json:"certificate_valid"`
	CertificateReused         bool   `json:"certificate_reused,omitempty"`
	ListenPort                int    `json:"listen_port"`
	ActiveListenPort          int    `json:"active_listen_port"`
	Configured                bool   `json:"configured"`
	SettingsConfigured        bool   `json:"settings_configured"`
	Subject                   string `json:"subject,omitempty"`
	ExpiresAt                 string `json:"expires_at,omitempty"`
	DaysRemaining             int    `json:"days_remaining,omitempty"`
	AutoRenewEnabled          bool   `json:"auto_renew_enabled"`
	ACMEEmail                 string `json:"acme_email,omitempty"`
	ACMEDNSProvider           string `json:"dns_provider,omitempty"`
	DNSAPITokenConfigured     bool   `json:"dns_api_token_configured"`
	ACMEStaging               bool   `json:"acme_staging"`
	RestartRequired           bool   `json:"restart_required"`
	Issuing                   bool   `json:"issuing"`
}

type panelCertificateManager struct {
	certFile   string
	keyFile    string
	accountDir string
	httpClient *http.Client

	mu                 sync.Mutex
	issuing            bool
	currentCertificate *tls.Certificate
}

type issuedPanelCertificate struct {
	certPEM     []byte
	keyPEM      []byte
	certificate tls.Certificate
}

type installedPanelCertificateBackup struct {
	certPEM      []byte
	keyPEM       []byte
	marker       []byte
	certExists   bool
	keyExists    bool
	markerExists bool
}

type cloudflareClient struct {
	token      string
	httpClient *http.Client
	apiBase    string
}

type cloudflareResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func panelTLSPaths(dbPath string) (certFile, keyFile string) {
	certFile = strings.TrimSpace(os.Getenv("PANEL_TLS_CERT_FILE"))
	keyFile = strings.TrimSpace(os.Getenv("PANEL_TLS_KEY_FILE"))
	if certFile != "" || keyFile != "" {
		return certFile, keyFile
	}
	if dbPath == "" || dbPath == ":memory:" || strings.HasPrefix(dbPath, "file:") {
		return "", ""
	}
	base := filepath.Join(filepath.Dir(dbPath), "tls")
	return filepath.Join(base, "fullchain.pem"), filepath.Join(base, "privkey.pem")
}

func newPanelCertificateManager(dbPath string, httpClient *http.Client) *panelCertificateManager {
	certFile, keyFile := panelTLSPaths(dbPath)
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	accountDir := ""
	if certFile != "" {
		accountDir = filepath.Dir(certFile)
	}
	return &panelCertificateManager{
		certFile:   certFile,
		keyFile:    keyFile,
		accountDir: accountDir,
		httpClient: httpClient,
	}
}

func (m *panelCertificateManager) status(settings PanelSettings, activePanelDomain, activeRouteDomain string, activeListenPort int, tlsEnabled bool) panelCertificateStatus {
	status := panelCertificateStatus{
		Available:          m != nil && m.certFile != "" && m.keyFile != "",
		TLSEnabled:         tlsEnabled,
		PanelDomain:        settings.PanelDomain,
		PanelPrefix:        panelPrefixForSettings(settings),
		RouteDomain:        settings.RouteDomain,
		WildcardDomain:     wildcardDomainForSettings(settings),
		ListenPort:         settings.ListenPort,
		ActiveListenPort:   activeListenPort,
		RestartRequired:    settings.TLSEnabled != tlsEnabled || settings.PanelDomain != activePanelDomain || settings.RouteDomain != activeRouteDomain || settings.ListenPort != activeListenPort,
		SettingsConfigured: settings.Configured && settings.PanelDomain != "" && settings.RouteDomain != "" && settings.ListenPort != 0,
	}
	if m == nil {
		return status
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	status.Issuing = m.issuing
	data, err := os.ReadFile(m.certFile) // #nosec G703 -- certFile is an administrator-configured TLS path captured when the certificate manager is created, never an HTTP request value.
	if err != nil {
		return status
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return status
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return status
	}
	status.Configured = true
	for _, name := range certificate.DNSNames {
		if strings.HasPrefix(name, "*.") {
			status.CertificateWildcardDomain = strings.ToLower(name)
			break
		}
	}
	status.CertificateCurrent = status.CertificateWildcardDomain != "" && status.CertificateWildcardDomain == status.WildcardDomain
	status.CertificateValid = time.Now().Before(certificate.NotAfter)
	status.Subject = certificate.Subject.CommonName
	status.ExpiresAt = certificate.NotAfter.UTC().Format(time.RFC3339)
	days := int(time.Until(certificate.NotAfter).Hours() / 24)
	if days < 0 {
		days = 0
	}
	status.DaysRemaining = days
	return status
}

func certificateNeedsRenewal(status panelCertificateStatus) bool {
	return !status.Configured || !status.CertificateCurrent || !status.CertificateValid || status.DaysRemaining <= int(panelCertificateRenewalWindow.Hours()/24)
}

func certificateCanBeReused(status panelCertificateStatus) bool {
	return status.CertificateCurrent && status.CertificateValid && !certificateNeedsRenewal(status)
}

func panelACMETokenKeyForSecret(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("meridian panel acme dns token v2\x00"))
	return mac.Sum(nil)
}

func legacyPanelACMETokenKeyForSecret(secret []byte) []byte {
	// codeql[go/weak-sensitive-data-hashing] -- legacy v1 ciphertext compatibility; new writes use HMAC-SHA256 v2.
	h := sha256.New()
	_, _ = h.Write([]byte("meridian panel acme dns token v1\x00"))
	_, _ = h.Write(secret)
	return h.Sum(nil)
}

func encryptPanelACMEToken(token string) (string, error) {
	return encryptPanelACMETokenWithSecret(token, activeStoredCredentialSecret())
}

func encryptPanelACMETokenWithSecret(token string, secret []byte) (string, error) {
	token = strings.TrimSpace(token)
	if len(token) < 20 || len(token) > 512 || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("a valid Cloudflare DNS API token is required")
	}
	block, err := aes.NewCipher(panelACMETokenKeyForSecret(secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(token), []byte("meridian-panel-acme"))
	return panelACMETokenCipherPrefix + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func decryptPanelACMEToken(ciphertext string) (string, error) {
	var lastErr error
	for _, secret := range storedCredentialSecrets() {
		plain, err := decryptPanelACMETokenWithSecret(ciphertext, secret)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func decryptPanelACMETokenWithSecret(ciphertext string, secret []byte) (string, error) {
	keyForSecret := panelACMETokenKeyForSecret
	prefix := panelACMETokenCipherPrefix
	if strings.HasPrefix(ciphertext, panelACMETokenLegacyCipherPrefix) {
		keyForSecret = legacyPanelACMETokenKeyForSecret
		prefix = panelACMETokenLegacyCipherPrefix
	} else if !strings.HasPrefix(ciphertext, panelACMETokenCipherPrefix) {
		return "", errors.New("invalid Cloudflare DNS API token ciphertext")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(ciphertext, prefix))
	if err != nil {
		return "", fmt.Errorf("decode Cloudflare DNS API token: %w", err)
	}
	block, err := aes.NewCipher(keyForSecret(secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(payload) < gcm.NonceSize()+gcm.Overhead() {
		return "", errors.New("invalid Cloudflare DNS API token ciphertext")
	}
	plain, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], []byte("meridian-panel-acme"))
	if err != nil {
		return "", fmt.Errorf("decrypt Cloudflare DNS API token: %w", err)
	}
	return string(plain), nil
}

func (m *panelCertificateManager) tlsConfig(enabled bool) (*tls.Config, bool, error) {
	if !enabled {
		return nil, false, nil
	}
	if m == nil || m.certFile == "" || m.keyFile == "" || m.accountDir == "" {
		return nil, false, errors.New("panel TLS certificate storage is unavailable")
	}
	certificate, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		return nil, false, fmt.Errorf("load panel TLS certificate: %w", err)
	}
	m.mu.Lock()
	m.currentCertificate = &certificate
	m.mu.Unlock()
	if err := writePrivateFileAtomic(filepath.Join(m.accountDir, "enabled"), []byte("enabled\n")); err != nil {
		return nil, false, fmt.Errorf("write panel TLS enabled marker: %w", err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.currentCertificate == nil {
				return nil, errors.New("panel TLS certificate is unavailable")
			}
			return m.currentCertificate, nil
		},
	}, true, nil
}

func validatePanelCertificateRequest(email, token string) error {
	email = strings.TrimSpace(email)
	address, err := mail.ParseAddress(email)
	if err != nil || !strings.EqualFold(address.Address, email) || len(email) > 254 {
		return errors.New("a valid ACME email address is required")
	}
	token = strings.TrimSpace(token)
	if len(token) < 20 || len(token) > 512 || strings.ContainsAny(token, "\r\n") {
		return errors.New("a valid Cloudflare DNS API token is required")
	}
	return nil
}

func (m *panelCertificateManager) issueCloudflare(ctx context.Context, email, token, panelDomain, routeDomain string, staging bool) (*issuedPanelCertificate, error) {
	settings, err := normalizeManagedPanelSettings(panelDomain, routeDomain)
	if err != nil {
		return nil, err
	}
	if m == nil || m.certFile == "" || m.keyFile == "" || m.accountDir == "" {
		return nil, errors.New("可写的 TLS 数据目录不可用")
	}
	if err := validatePanelCertificateRequest(email, token); err != nil {
		return nil, err
	}
	m.mu.Lock()
	if m.issuing {
		m.mu.Unlock()
		return nil, errCertificateIssuanceBusy
	}
	m.issuing = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.issuing = false
		m.mu.Unlock()
	}()

	if err := os.MkdirAll(m.accountDir, 0o700); err != nil {
		return nil, fmt.Errorf("create TLS directory: %w", err)
	}
	directoryURL := letsEncryptProductionDirectory
	accountName := "acme-account.pem"
	if staging {
		directoryURL = letsEncryptStagingDirectory
		accountName = "acme-account-staging.pem"
	}
	accountKey, err := loadOrCreateACMEAccountKey(m.accountDir, accountName)
	if err != nil {
		return nil, err
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: directoryURL, UserAgent: "Meridian/" + appVersion}
	_, err = client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + strings.TrimSpace(email)}}, acme.AcceptTOS)
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("register ACME account: %w", err)
	}

	wildcard := "*." + settings.RouteDomain
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(wildcard))
	if err != nil {
		return nil, fmt.Errorf("create ACME order: %w", err)
	}
	cf := &cloudflareClient{token: strings.TrimSpace(token), httpClient: m.httpClient, apiBase: "https://api.cloudflare.com/client/v4"}
	for _, authorizationURL := range order.AuthzURLs {
		if err := fulfillCloudflareDNSAuthorization(ctx, client, cf, authorizationURL, settings.RouteDomain); err != nil {
			return nil, err
		}
	}
	readyOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("wait for ACME order: %w", err)
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate certificate key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{wildcard}}, certificateKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate request: %w", err)
	}
	chain, _, err := client.CreateOrderCert(ctx, readyOrder.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("issue certificate: %w", err)
	}
	certPEM := make([]byte, 0, len(chain)*1024)
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificateKey)
	if err != nil {
		return nil, fmt.Errorf("encode certificate key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("validate issued certificate pair: %w", err)
	}
	return &issuedPanelCertificate{certPEM: certPEM, keyPEM: keyPEM, certificate: certificate}, nil
}

func (m *panelCertificateManager) install(issued *issuedPanelCertificate, activate bool) error {
	if m == nil || issued == nil || m.certFile == "" || m.keyFile == "" || m.accountDir == "" {
		return errors.New("issued panel certificate is unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := writePrivateFileAtomic(m.keyFile, issued.keyPEM); err != nil {
		return fmt.Errorf("write certificate key: %w", err)
	}
	if err := writePrivateFileAtomic(m.certFile, issued.certPEM); err != nil {
		return fmt.Errorf("write certificate chain: %w", err)
	}
	if err := writePrivateFileAtomic(filepath.Join(m.accountDir, "enabled"), []byte("enabled\n")); err != nil {
		return fmt.Errorf("write panel TLS enabled marker: %w", err)
	}
	if activate {
		certificate := issued.certificate
		m.currentCertificate = &certificate
	}
	return nil
}

func (m *panelCertificateManager) activate(issued *issuedPanelCertificate) {
	if m == nil || issued == nil {
		return
	}
	m.mu.Lock()
	certificate := issued.certificate
	m.currentCertificate = &certificate
	m.mu.Unlock()
}

// disable clears the active in-memory certificate and marker without deleting
// the certificate files. Keeping the files allows a later manual issuance or
// renewal to reuse the existing storage after the panel has fallen back to
// HTTP.
func (m *panelCertificateManager) disable() error {
	if m == nil || m.accountDir == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentCertificate = nil
	err := os.Remove(filepath.Join(m.accountDir, "enabled")) // #nosec G703 -- accountDir is the managed TLS directory and enabled is a fixed marker basename.
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func readOptionalFile(filename string) ([]byte, bool, error) {
	if filename == "" || filepath.Base(filename) == "." || filepath.Base(filename) == string(filepath.Separator) {
		return nil, false, errors.New("invalid TLS file path")
	}
	root, err := os.OpenRoot(filepath.Dir(filename))
	if err != nil {
		return nil, false, err
	}
	file, err := root.Open(filepath.Base(filename))
	if err != nil {
		_ = root.Close()
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 1<<20))
	closeErr := file.Close()
	rootErr := root.Close()
	if readErr != nil {
		return nil, false, readErr
	}
	if closeErr != nil {
		return nil, false, closeErr
	}
	if rootErr != nil {
		return nil, false, rootErr
	}
	return data, true, nil
}

func (m *panelCertificateManager) backupInstalledFiles() (installedPanelCertificateBackup, error) {
	if m == nil || m.certFile == "" || m.keyFile == "" || m.accountDir == "" {
		return installedPanelCertificateBackup{}, errors.New("panel TLS certificate storage is unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var backup installedPanelCertificateBackup
	var err error
	if backup.certPEM, backup.certExists, err = readOptionalFile(m.certFile); err != nil {
		return installedPanelCertificateBackup{}, fmt.Errorf("back up certificate chain: %w", err)
	}
	if backup.keyPEM, backup.keyExists, err = readOptionalFile(m.keyFile); err != nil {
		return installedPanelCertificateBackup{}, fmt.Errorf("back up certificate key: %w", err)
	}
	markerFile := filepath.Join(m.accountDir, "enabled")
	if backup.marker, backup.markerExists, err = readOptionalFile(markerFile); err != nil {
		return installedPanelCertificateBackup{}, fmt.Errorf("back up TLS marker: %w", err)
	}
	return backup, nil
}

func restoreOptionalFile(filename string, data []byte, existed bool) error {
	if existed {
		return writePrivateFileAtomic(filename, data)
	}
	err := os.Remove(filename) // #nosec G703 -- callers pass only the manager's certificate, private-key, or fixed enabled-marker path.
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (m *panelCertificateManager) restoreInstalledFiles(backup installedPanelCertificateBackup) error {
	if m == nil || m.certFile == "" || m.keyFile == "" || m.accountDir == "" {
		return errors.New("panel TLS certificate storage is unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := restoreOptionalFile(m.keyFile, backup.keyPEM, backup.keyExists); err != nil {
		return fmt.Errorf("restore certificate key: %w", err)
	}
	if err := restoreOptionalFile(m.certFile, backup.certPEM, backup.certExists); err != nil {
		return fmt.Errorf("restore certificate chain: %w", err)
	}
	if err := restoreOptionalFile(filepath.Join(m.accountDir, "enabled"), backup.marker, backup.markerExists); err != nil {
		return fmt.Errorf("restore TLS marker: %w", err)
	}
	return nil
}

func loadOrCreateACMEAccountKey(directory, filename string) (crypto.Signer, error) {
	if filename == "" || filename != filepath.Base(filename) {
		return nil, errors.New("ACME account key filename must be a base name")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open ACME account directory: %w", err)
	}
	file, err := root.Open(filename)
	if err == nil {
		const maxAccountKeyBytes = 64 << 10
		data, readErr := io.ReadAll(io.LimitReader(file, maxAccountKeyBytes+1))
		closeErr := file.Close()
		rootCloseErr := root.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read ACME account key: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close ACME account key: %w", closeErr)
		}
		if rootCloseErr != nil {
			return nil, fmt.Errorf("close ACME account directory: %w", rootCloseErr)
		}
		if len(data) > maxAccountKeyBytes {
			return nil, errors.New("stored ACME account key is too large")
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("stored ACME account key is invalid")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ACME account key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("stored ACME account key is not a signer")
		}
		return signer, nil
	}
	if closeErr := root.Close(); closeErr != nil {
		return nil, fmt.Errorf("close ACME account directory: %w", closeErr)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read ACME account key: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ACME account key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode ACME account key: %w", err)
	}
	if err := writePrivateFileAtomic(filepath.Join(directory, filename), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, fmt.Errorf("write ACME account key: %w", err)
	}
	return key, nil
}

func writePrivateFileAtomic(filename string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil { // #nosec G703 G304 -- filename is generated from the configured private TLS directory.
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(filename), ".meridian-tls-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) { // #nosec G703 G304 -- filename is generated from the configured private TLS directory.
			return err
		}
	}
	return os.Rename(tmpName, filename) // #nosec G703 G304 -- both paths are generated within the private TLS directory.
}

func fulfillCloudflareDNSAuthorization(ctx context.Context, acmeClient *acme.Client, cf *cloudflareClient, authorizationURL, routeDomain string) error {
	authorization, err := acmeClient.GetAuthorization(ctx, authorizationURL)
	if err != nil {
		return fmt.Errorf("get ACME authorization: %w", err)
	}
	if authorization.Status == acme.StatusValid {
		return nil
	}
	var challenge *acme.Challenge
	for _, candidate := range authorization.Challenges {
		if candidate.Type == "dns-01" {
			challenge = candidate
			break
		}
	}
	if challenge == nil {
		return errors.New("ACME server did not offer a DNS-01 challenge")
	}
	value, err := acmeClient.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return fmt.Errorf("prepare DNS-01 challenge: %w", err)
	}
	zoneName, err := publicsuffix.EffectiveTLDPlusOne(routeDomain)
	if err != nil {
		return fmt.Errorf("resolve DNS zone: %w", err)
	}
	zoneID, err := cf.findZone(ctx, zoneName)
	if err != nil {
		return err
	}
	recordName := "_acme-challenge." + strings.TrimPrefix(authorization.Identifier.Value, "*.")
	recordID, err := cf.createTXTRecord(ctx, zoneID, recordName, value)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = cf.deleteRecord(cleanupCtx, zoneID, recordID)
	}()
	if err := waitForTXTRecord(ctx, recordName, value); err != nil {
		return err
	}
	if _, err := acmeClient.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("accept DNS-01 challenge: %w", err)
	}
	if _, err := acmeClient.WaitAuthorization(ctx, authorization.URI); err != nil {
		return fmt.Errorf("validate DNS-01 challenge: %w", err)
	}
	return nil
}

func waitForTXTRecord(ctx context.Context, name, value string) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	timeout := time.NewTimer(2 * time.Minute)
	defer timeout.Stop()
	for {
		records, err := net.DefaultResolver.LookupTXT(ctx, name)
		if err == nil {
			for _, record := range records {
				if record == value {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return fmt.Errorf("DNS-01 record %s did not propagate within two minutes", name)
		case <-ticker.C:
		}
	}
}

func (c *cloudflareClient) request(ctx context.Context, method, requestPath string, body io.Reader) (json.RawMessage, error) {
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.apiBase, "/")+requestPath, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("Cloudflare DNS request failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read Cloudflare DNS response: %w", err)
	}
	var envelope cloudflareResponse
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, errors.New("Cloudflare DNS returned an invalid response")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		message := "Cloudflare DNS request was rejected"
		if len(envelope.Errors) > 0 && strings.TrimSpace(envelope.Errors[0].Message) != "" {
			message += ": " + strings.TrimSpace(envelope.Errors[0].Message)
		}
		return nil, errors.New(message)
	}
	return envelope.Result, nil
}

func (c *cloudflareClient) findZone(ctx context.Context, zoneName string) (string, error) {
	result, err := c.request(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(zoneName)+"&status=active&per_page=1", nil)
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(result, &zones); err != nil || len(zones) == 0 || zones[0].ID == "" {
		return "", fmt.Errorf("Cloudflare DNS zone %s was not found", zoneName)
	}
	return zones[0].ID, nil
}

func (c *cloudflareClient) createTXTRecord(ctx context.Context, zoneID, name, value string) (string, error) {
	body, err := json.Marshal(map[string]interface{}{"type": "TXT", "name": name, "content": value, "ttl": 60})
	if err != nil {
		return "", err
	}
	result, err := c.request(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	var record struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(result, &record); err != nil || record.ID == "" {
		return "", errors.New("Cloudflare DNS did not return the challenge record ID")
	}
	return record.ID, nil
}

func (c *cloudflareClient) deleteRecord(ctx context.Context, zoneID, recordID string) error {
	_, err := c.request(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil)
	return err
}
