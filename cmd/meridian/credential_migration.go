package main

import "fmt"

// migrateStoredCredentialCiphertexts upgrades PR #50 credentials that were
// derived from JWT_SECRET to the dedicated MERIDIAN_SECRET_KEY. It never
// returns or logs plaintext credentials.
func migrateStoredCredentialCiphertexts(db *DB) error {
	if db == nil || !meridianSecretKeyConfigured {
		return nil
	}
	var panelCipher string
	if err := db.db.QueryRow("SELECT acme_token_ciphertext FROM panel_settings WHERE id=1").Scan(&panelCipher); err != nil {
		return fmt.Errorf("read panel credential ciphertext: %w", err)
	}
	if panelCipher != "" {
		if _, err := decryptPanelACMETokenWithSecret(panelCipher, meridianSecretKey); err != nil {
			plain, legacyErr := decryptPanelACMETokenWithSecret(panelCipher, jwtSecret)
			if legacyErr != nil {
				return fmt.Errorf("decrypt legacy panel credential: %w", legacyErr)
			}
			ciphertext, encErr := encryptPanelACMETokenWithSecret(plain, meridianSecretKey)
			if encErr != nil {
				return fmt.Errorf("re-encrypt panel credential: %w", encErr)
			}
			if _, err := db.db.Exec("UPDATE panel_settings SET acme_token_ciphertext=? WHERE id=1", ciphertext); err != nil {
				return fmt.Errorf("store migrated panel credential: %w", err)
			}
		}
	}

	var telegramCipher string
	if err := db.db.QueryRow("SELECT bot_token_ciphertext FROM telegram_report_settings WHERE id=1").Scan(&telegramCipher); err != nil {
		return fmt.Errorf("read Telegram credential ciphertext: %w", err)
	}
	if telegramCipher != "" {
		if _, err := decryptTelegramBotTokenWithSecret(telegramCipher, meridianSecretKey); err != nil {
			plain, legacyErr := decryptTelegramBotTokenWithSecret(telegramCipher, jwtSecret)
			if legacyErr != nil {
				return fmt.Errorf("decrypt legacy Telegram credential: %w", legacyErr)
			}
			ciphertext, encErr := encryptTelegramBotTokenWithSecret(plain, meridianSecretKey)
			if encErr != nil {
				return fmt.Errorf("re-encrypt Telegram credential: %w", encErr)
			}
			if _, err := db.db.Exec("UPDATE telegram_report_settings SET bot_token_ciphertext=? WHERE id=1", ciphertext); err != nil {
				return fmt.Errorf("store migrated Telegram credential: %w", err)
			}
		}
	}
	return nil
}
