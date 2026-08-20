package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func runCommandLine(args []string, input io.Reader, output io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "--version", "-v":
		if len(args) != 1 {
			return true, errors.New("version command does not accept arguments")
		}
		_, err := fmt.Fprintln(output, appVersion)
		return true, err
	case "--healthcheck":
		if len(args) != 1 {
			return true, errors.New("healthcheck command does not accept arguments")
		}
		return true, runHealthcheckCommand()
	case "admin":
		return true, runAdminCommand(args[1:], input, output)
	default:
		return false, nil
	}
}

func healthcheckPanelDomain(dbPath string) string {
	domain := strings.TrimSpace(os.Getenv("PANEL_DOMAIN"))
	if domain == "" && strings.TrimSpace(dbPath) != "" && dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:") {
		db, err := sql.Open("sqlite", dbPath)
		if err == nil {
			defer db.Close()
			_ = db.QueryRow(`SELECT panel_domain FROM panel_settings WHERE id=1`).Scan(&domain)
		}
	}
	if domain == "" {
		return ""
	}
	domain, err := normalizePublicHost(domain)
	if err != nil {
		return ""
	}
	return domain
}

func healthcheckTLSConfig(dbPath string) (*tls.Config, string) {
	serverName := healthcheckPanelDomain(dbPath)
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	certFile, _ := panelTLSPaths(dbPath)
	if certFile != "" {
		// #nosec G304 -- certFile is an administrator-configured panel TLS path, not request data.
		if data, readErr := os.ReadFile(certFile); readErr == nil {
			// Trust the administrator-installed panel chain for the local probe,
			// while still performing normal TLS chain and hostname validation.
			roots.AppendCertsFromPEM(data)
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName}, serverName
}

func runHealthcheckCommand() error {
	dbPath := strings.TrimSpace(os.Getenv("DB_PATH"))
	if dbPath == "" {
		dbPath = "/app/data/meridian.db"
	}
	markerPath := filepath.Join(filepath.Dir(dbPath), "panel-port")
	// #nosec G703 G304 -- DB_PATH is an administrator-controlled local database location; this only reads the sibling panel-port marker written by Meridian itself.
	marker, err := os.ReadFile(markerPath)
	if err != nil {
		return fmt.Errorf("read panel port: %w", err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(marker)))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid panel port %q", strings.TrimSpace(string(marker)))
	}

	tlsConfig, _ := healthcheckTLSConfig(dbPath)
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   4 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var lastErr error
	hosts := []string{"127.0.0.1", "::1"}
	for _, scheme := range []string{"https", "http"} {
		for _, host := range hosts {
			endpoint := fmt.Sprintf("%s://%s/api/auth/check", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
			// #nosec G704 -- scheme and host are selected from fixed loopback lists, path is constant, and port is range-validated.
			resp, requestErr := client.Get(endpoint)
			if requestErr != nil {
				lastErr = requestErr
				continue
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			closeErr := resp.Body.Close()
			if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices && closeErr == nil {
				return nil
			}
			lastErr = fmt.Errorf("%s returned HTTP %d", endpoint, resp.StatusCode)
		}
	}
	return fmt.Errorf("panel healthcheck failed: %w", lastErr)
}

func runAdminCommand(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 || args[0] != "reset-password" {
		return errors.New("usage: meridian admin reset-password --db <path> --password-stdin")
	}
	var dbPath string
	passwordStdin := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if dbPath != "" || i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return errors.New("--db requires exactly one non-empty path")
			}
			dbPath = args[i+1]
			i++
		case "--password-stdin":
			if passwordStdin {
				return errors.New("--password-stdin may only be specified once")
			}
			passwordStdin = true
		default:
			return errors.New("unknown reset-password argument")
		}
	}
	if dbPath == "" || !passwordStdin {
		return errors.New("usage: meridian admin reset-password --db <path> --password-stdin")
	}

	password, err := readPasswordLine(input)
	if err != nil {
		return err
	}
	db, err := openDB(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	if err := db.ResetAdminPassword(password); err != nil {
		return fmt.Errorf("reset administrator password: %w", err)
	}
	_, err = fmt.Fprintln(output, "administrator password updated")
	return err
}

func readPasswordLine(input io.Reader) (string, error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64), 74)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return "", errors.New("password input is empty")
	}
	password := strings.TrimSuffix(scanner.Text(), "\r")
	if scanner.Scan() {
		return "", errors.New("password input must contain exactly one line")
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if err := validateAdminPassword(password); err != nil {
		return "", err
	}
	return password, nil
}

func panelListenAddress(bindAddress string, port int) (string, error) {
	bindAddress = strings.TrimSpace(bindAddress)
	if bindAddress == "" {
		bindAddress = "127.0.0.1"
	}
	if net.ParseIP(bindAddress) == nil {
		return "", fmt.Errorf("PANEL_BIND_ADDR must be an IP address, got %q", bindAddress)
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("panel port must be between 1 and 65535, got %d", port)
	}
	return net.JoinHostPort(bindAddress, strconv.Itoa(port)), nil
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func panelTLSConfigFromEnv(dbPath string) (*tls.Config, bool, error) {
	return newPanelCertificateManager(dbPath, nil).tlsConfig(envBool("PANEL_TLS_ENABLED"))
}

func panelPortMarkerPath(dbPath string) string {
	if dbPath == "" || dbPath == ":memory:" || strings.HasPrefix(dbPath, "file:") {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), "panel-port")
}
