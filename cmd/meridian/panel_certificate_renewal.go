package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

func runPanelCertificateRenewalScheduler(ctx context.Context, db *DB, manager *panelCertificateManager, restart ...func()) {
	if db == nil || manager == nil {
		return
	}
	check := func() {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		disabled, err := disableExpiredPanelTLSIfNeeded(db, manager)
		if err != nil {
			log.Printf("[panel-certificate] automatic HTTPS fallback failed: %v", err)
			return
		}
		if disabled {
			if len(restart) > 0 && restart[0] != nil {
				restart[0]()
			}
			return
		}
		if err := renewPanelCertificateIfDue(checkCtx, db, manager); err != nil && !errors.Is(err, errCertificateIssuanceBusy) && !errors.Is(err, context.Canceled) {
			log.Printf("[panel-certificate] automatic renewal failed: %v", err)
		}
	}
	go check()
	ticker := time.NewTicker(panelCertificateRenewalInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			check()
		case <-ctx.Done():
			return
		}
	}
}

// disableExpiredPanelTLSIfNeeded makes an expired certificate a recoverable
// configuration state. The certificate files are intentionally preserved;
// only the active database flag and marker are cleared before a restart.
func disableExpiredPanelTLSIfNeeded(db *DB, manager *panelCertificateManager) (bool, error) {
	if db == nil || manager == nil {
		return false, nil
	}
	settings, err := db.PanelSettings()
	if err != nil {
		return false, err
	}
	if !settings.TLSEnabled || !settings.Configured || settings.PanelDomain == "" || settings.RouteDomain == "" {
		return false, nil
	}
	status := manager.status(settings, settings.PanelDomain, settings.RouteDomain, settings.ListenPort, settings.TLSEnabled)
	if status.Issuing || !status.Configured || status.CertificateValid {
		return false, nil
	}
	if err := db.SetPanelTLSEnabled(false); err != nil {
		return false, fmt.Errorf("disable expired panel TLS in settings: %w", err)
	}
	if err := manager.disable(); err != nil {
		return false, fmt.Errorf("disable expired panel TLS marker: %w", err)
	}
	log.Printf("[panel-certificate] certificate for *.%s expired; HTTPS disabled and HTTP fallback requested", settings.RouteDomain)
	return true, nil
}

func renewPanelCertificateIfDue(ctx context.Context, db *DB, manager *panelCertificateManager) error {
	settings, err := db.PanelSettings()
	if err != nil {
		return err
	}
	if !settings.TLSEnabled || !settings.Configured || settings.PanelDomain == "" || settings.RouteDomain == "" {
		return nil
	}
	if jwtSecretEphemeral || strings.TrimSpace(settings.ACMEEmail) == "" || strings.TrimSpace(settings.ACMETokenCiphertext) == "" {
		return nil
	}
	status := manager.status(settings, settings.PanelDomain, settings.RouteDomain, settings.ListenPort, settings.TLSEnabled)
	if !certificateNeedsRenewal(status) {
		return nil
	}
	token, err := decryptPanelACMEToken(settings.ACMETokenCiphertext)
	if err != nil {
		return errors.New("无法解密已保存的 DNS API Token")
	}
	provider := strings.ToLower(strings.TrimSpace(settings.ACMEDNSProvider))
	if provider == "" {
		provider = "cloudflare"
	}
	if provider != "cloudflare" {
		return errors.New("自动续签暂仅支持 Cloudflare DNS")
	}
	issued, err := manager.issueCloudflare(ctx, settings.ACMEEmail, token, settings.PanelDomain, settings.RouteDomain, settings.ACMEStaging)
	if err != nil {
		return err
	}
	backup, err := manager.backupInstalledFiles()
	if err != nil {
		return err
	}
	if err := manager.install(issued, true); err != nil {
		_ = manager.restoreInstalledFiles(backup)
		return err
	}
	log.Printf("[panel-certificate] wildcard certificate renewed for *.%s", settings.RouteDomain)
	return nil
}
