package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
	_ "modernc.org/sqlite"
)

const (
	backupMagic              = "MRDBKP01"
	backupFormatVersion      = 1
	backupSaltBytes          = 16
	backupMaxUploadBytes     = 256 << 20
	backupMaxExpandedBytes   = 512 << 20
	backupMaxFiles           = 8
	backupMinPasswordBytes   = 12
	backupMaxPasswordBytes   = 128
	backupPendingSuffix      = ".restore-pending"
	backupAppliedSuffix      = ".restore-applied"
	backupRollbackSuffix     = ".restore-rollback"
	backupDatabaseEntry      = "meridian.db"
	backupManifestEntry      = "manifest.json"
	backupTLSCertificate     = "tls/fullchain.pem"
	backupTLSPrivateKey      = "tls/privkey.pem"
	backupTLSEnabled         = "tls/enabled"
	backupACMEAccount        = "tls/acme-account.pem"
	backupACMEAccountStaging = "tls/acme-account-staging.pem"
)

var backupAllowedEntries = map[string]int64{
	backupManifestEntry:      1 << 20,
	backupDatabaseEntry:      backupMaxExpandedBytes,
	backupTLSCertificate:     4 << 20,
	backupTLSPrivateKey:      1 << 20,
	backupTLSEnabled:         64,
	backupACMEAccount:        1 << 20,
	backupACMEAccountStaging: 1 << 20,
}

type backupManifest struct {
	Format            string   `json:"format"`
	FormatVersion     int      `json:"format_version"`
	AppVersion        string   `json:"app_version"`
	CreatedAt         string   `json:"created_at"`
	Files             []string `json:"files"`
	IncludeTLS        *bool    `json:"include_tls,omitempty"`
	JWTSecret         string   `json:"jwt_secret"`                  // #nosec G117 -- encrypted backup manifest field; it is never logged or persisted outside the encrypted archive.
	CredentialSecret  string   `json:"credential_secret,omitempty"` // #nosec G117 -- encrypted backup manifest field; it is required to migrate dedicated credential ciphertexts.
	UpstreamHeaderKey string   `json:"upstream_header_key"`
}

type restoreAppliedState struct {
	RollbackDir string
}

type restoreMarker struct {
	Files      []string `json:"files"`
	IncludeTLS *bool    `json:"include_tls,omitempty"`
}

type backupPanelSettings struct {
	PanelDomain         string
	RouteDomain         string
	ListenPort          int
	TLSEnabled          int
	Configured          int
	ACMEEmail           string
	ACMEDNSProvider     string
	ACMETokenCiphertext string
	ACMEStaging         int
}

func boolPointer(value bool) *bool { return &value }

func manifestIncludesTLS(manifest backupManifest) bool {
	// Backups created before include_tls was introduced always included TLS.
	return manifest.IncludeTLS == nil || *manifest.IncludeTLS
}

func markerIncludesTLS(marker restoreMarker) bool {
	// Pending restores created before include_tls was introduced always replaced TLS.
	return marker.IncludeTLS == nil || *marker.IncludeTLS
}

func restoreDirectoryIncludesTLS(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "restore.json")) // #nosec G304 G703 -- dir is an internal rollback directory created by Meridian.
	if err != nil {
		// Restores created before include_tls was introduced always replaced TLS.
		return true
	}
	var marker restoreMarker
	if json.Unmarshal(data, &marker) != nil {
		return true
	}
	return markerIncludesTLS(marker)
}

func validateBackupPassword(password string) error {
	if len(password) < backupMinPasswordBytes || len(password) > backupMaxPasswordBytes {
		return fmt.Errorf("备份密码必须为 %d-%d 个字节", backupMinPasswordBytes, backupMaxPasswordBytes)
	}
	return nil
}

func backupKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
}

func sealBackup(plain []byte, password string) ([]byte, error) {
	if err := validateBackupPassword(password); err != nil {
		return nil, err
	}
	salt := make([]byte, backupSaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("生成备份盐值: %w", err)
	}
	key, err := backupKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("派生备份密钥: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成备份随机数: %w", err)
	}
	header := append([]byte(backupMagic), salt...)
	if len(nonce) > 255 {
		return nil, errors.New("backup nonce is too large")
	}
	header = append(header, byte(len(nonce))) // #nosec G115 -- nonce length is bounded by the AES-GCM implementation and checked above.
	header = append(header, nonce...)
	sealed := gcm.Seal(nil, nonce, plain, header)
	return append(header, sealed...), nil
}

func openBackup(payload []byte, password string) ([]byte, error) {
	if err := validateBackupPassword(password); err != nil {
		return nil, err
	}
	minimum := len(backupMagic) + backupSaltBytes + 1
	if len(payload) < minimum || string(payload[:len(backupMagic)]) != backupMagic {
		return nil, errors.New("不是有效的 Meridian 备份文件")
	}
	saltStart := len(backupMagic)
	salt := payload[saltStart : saltStart+backupSaltBytes]
	nonceLen := int(payload[saltStart+backupSaltBytes])
	headerLen := minimum + nonceLen
	if nonceLen < 1 || headerLen >= len(payload) {
		return nil, errors.New("备份文件头损坏")
	}
	key, err := backupKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("派生备份密钥: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if nonceLen != gcm.NonceSize() || len(payload)-headerLen < gcm.Overhead() {
		return nil, errors.New("备份文件头损坏")
	}
	plain, err := gcm.Open(nil, payload[minimum:headerLen], payload[headerLen:], payload[:headerLen])
	if err != nil {
		return nil, errors.New("备份密码错误或文件已被篡改")
	}
	return plain, nil
}

func quoteSQLiteString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func (a *App) databaseSnapshot() (string, func(), error) {
	if a == nil || a.db == nil || a.dbPath == "" || a.dbPath == ":memory:" || strings.HasPrefix(a.dbPath, "file:") {
		return "", func() {}, errors.New("当前数据库模式不支持备份")
	}
	if a.pm != nil {
		a.pm.FlushTraffic()
	}
	if err := a.db.flushDynamicObservations(); err != nil {
		return "", func() {}, fmt.Errorf("刷新日志队列: %w", err)
	}
	dir, err := os.MkdirTemp(filepath.Dir(a.dbPath), ".meridian-backup-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	snapshot := filepath.Join(dir, backupDatabaseEntry)
	if _, err := a.db.db.Exec("VACUUM INTO " + quoteSQLiteString(snapshot)); err != nil { // #nosec G202 -- snapshot is created in a private temporary directory and quoteSQLiteString escapes the complete literal.
		cleanup()
		return "", func() {}, fmt.Errorf("创建 SQLite 一致性快照: %w", err)
	}
	if err := hardenDatabaseFilePermissions(snapshot); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return snapshot, cleanup, nil
}

func addZipFile(writer *zip.Writer, name, path string) (bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is selected from internal database/TLS files before entering the archive.
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(0o600)
	header.Modified = time.Unix(0, 0).UTC()
	entry, err := writer.CreateHeader(header)
	if err != nil {
		return false, err
	}
	_, err = entry.Write(data)
	return true, err
}

func (a *App) buildBackup(password string, includeTLS bool) ([]byte, error) {
	if err := validateBackupPassword(password); err != nil {
		return nil, err
	}
	snapshot, cleanup, err := a.databaseSnapshot()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	files := []string{backupDatabaseEntry}
	if _, err := addZipFile(zipWriter, backupDatabaseEntry, snapshot); err != nil {
		return nil, err
	}
	if includeTLS {
		certFile, keyFile := panelTLSPaths(a.dbPath)
		tlsCandidates := []struct{ name, path string }{
			{backupTLSCertificate, certFile},
			{backupTLSPrivateKey, keyFile},
		}
		if certFile != "" {
			tlsDir := filepath.Dir(certFile)
			tlsCandidates = append(tlsCandidates,
				struct{ name, path string }{backupTLSEnabled, filepath.Join(tlsDir, "enabled")},
				struct{ name, path string }{backupACMEAccount, filepath.Join(tlsDir, "acme-account.pem")},
				struct{ name, path string }{backupACMEAccountStaging, filepath.Join(tlsDir, "acme-account-staging.pem")},
			)
		}
		for _, candidate := range tlsCandidates {
			if candidate.path == "" {
				continue
			}
			added, err := addZipFile(zipWriter, candidate.name, candidate.path)
			if err != nil {
				return nil, fmt.Errorf("读取 %s: %w", candidate.name, err)
			}
			if added {
				files = append(files, candidate.name)
			}
		}
	}
	manifest := backupManifest{
		Format:            "meridian-backup",
		FormatVersion:     backupFormatVersion,
		AppVersion:        appVersion,
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
		Files:             files,
		IncludeTLS:        boolPointer(includeTLS),
		JWTSecret:         base64.RawStdEncoding.EncodeToString(jwtSecret),
		CredentialSecret:  base64.RawStdEncoding.EncodeToString(activeStoredCredentialSecret()),
		UpstreamHeaderKey: base64.RawStdEncoding.EncodeToString(a.pm.upstreamHeaderKey),
	}
	manifestData, err := json.Marshal(manifest) // #nosec G117 -- the manifest is immediately encrypted before it leaves the process.
	if err != nil {
		return nil, err
	}
	header := &zip.FileHeader{Name: backupManifestEntry, Method: zip.Deflate}
	header.SetMode(0o600)
	header.Modified = time.Unix(0, 0).UTC()
	entry, err := zipWriter.CreateHeader(header)
	if err != nil {
		return nil, err
	}
	if _, err := entry.Write(manifestData); err != nil {
		return nil, err
	}
	if err := zipWriter.Close(); err != nil {
		return nil, err
	}
	return sealBackup(archive.Bytes(), password)
}

func readZipEntry(file *zip.File, maxBytes int64) ([]byte, error) {
	if file.UncompressedSize64 > uint64(maxBytes) { // #nosec G115 -- maxBytes is a positive, fixed per-entry limit selected by Meridian.
		return nil, fmt.Errorf("%s 解压后过大", file.Name)
	}
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s 解压后过大", file.Name)
	}
	return data, nil
}

func parseBackupArchive(plain []byte) (backupManifest, map[string][]byte, error) {
	var manifest backupManifest
	reader, err := zip.NewReader(bytes.NewReader(plain), int64(len(plain)))
	if err != nil {
		return manifest, nil, errors.New("备份压缩包损坏")
	}
	if len(reader.File) < 2 || len(reader.File) > backupMaxFiles {
		return manifest, nil, errors.New("备份文件数量无效")
	}
	entries := make(map[string][]byte, len(reader.File))
	var expanded int64
	for _, file := range reader.File {
		limit, allowed := backupAllowedEntries[file.Name]
		if !allowed || filepath.ToSlash(filepath.Clean(file.Name)) != file.Name || strings.HasPrefix(file.Name, "/") {
			return manifest, nil, fmt.Errorf("备份包含不允许的文件: %s", file.Name)
		}
		if _, duplicate := entries[file.Name]; duplicate {
			return manifest, nil, fmt.Errorf("备份包含重复文件: %s", file.Name)
		}
		data, err := readZipEntry(file, limit)
		if err != nil {
			return manifest, nil, err
		}
		expanded += int64(len(data))
		if expanded > backupMaxExpandedBytes {
			return manifest, nil, errors.New("备份解压后总大小超出限制")
		}
		entries[file.Name] = data
	}
	manifestData, ok := entries[backupManifestEntry]
	if !ok {
		return manifest, nil, errors.New("备份缺少清单")
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, nil, errors.New("备份清单无效")
	}
	if manifest.Format != "meridian-backup" || manifest.FormatVersion != backupFormatVersion {
		return manifest, nil, errors.New("不支持的备份格式版本")
	}
	if !manifestIncludesTLS(manifest) {
		for name := range entries {
			if strings.HasPrefix(name, "tls/") {
				return manifest, nil, errors.New("备份清单声明不包含 TLS，但压缩包中存在 TLS 文件")
			}
		}
	}
	if _, ok := entries[backupDatabaseEntry]; !ok {
		return manifest, nil, errors.New("备份缺少数据库")
	}
	declared := make(map[string]bool, len(manifest.Files)+1)
	declared[backupManifestEntry] = true
	for _, name := range manifest.Files {
		if _, ok := backupAllowedEntries[name]; !ok || name == backupManifestEntry || declared[name] {
			return manifest, nil, errors.New("备份清单文件列表无效")
		}
		declared[name] = true
	}
	if len(declared) != len(entries) {
		return manifest, nil, errors.New("备份清单与文件内容不一致")
	}
	for name := range entries {
		if !declared[name] {
			return manifest, nil, errors.New("备份清单与文件内容不一致")
		}
	}
	return manifest, entries, nil
}

func validateSQLiteBackup(path string) error {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return err
	}
	defer db.Close()
	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("SQLite 完整性检查失败: %s", result)
	}
	var users, sites int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&users); err != nil {
		return errors.New("备份数据库缺少用户数据表")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sites").Scan(&sites); err != nil {
		return errors.New("备份数据库缺少站点数据表")
	}
	if users < 1 {
		return errors.New("备份中没有管理员账户")
	}
	return nil
}

func reencryptRestoredSecrets(path string, oldJWT, oldCredentialKey, oldHeaderKey, newJWT, newCredentialKey, newHeaderKey []byte) error {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT id, target_url, upstream_headers FROM sites WHERE upstream_headers <> '' AND upstream_headers <> '[]'")
	if err != nil {
		return err
	}
	type update struct {
		id  int64
		raw string
	}
	var updates []update
	for rows.Next() {
		var id int64
		var targetURL, raw string
		if err := rows.Scan(&id, &targetURL, &raw); err != nil {
			rows.Close()
			return err
		}
		stored, err := parseStoredUpstreamHeaders(raw)
		if err != nil {
			rows.Close()
			return fmt.Errorf("站点 %d 的自定义请求头无效: %w", id, err)
		}
		target, err := normalizeTargetURL(targetURL)
		if err != nil {
			rows.Close()
			return fmt.Errorf("站点 %d 的目标地址无效: %w", id, err)
		}
		authority := redirectHostKey(target)
		for i := range stored {
			value, err := decryptUpstreamHeaderValue(stored[i].Name, stored[i].Ciphertext, authority, oldHeaderKey)
			if err != nil {
				rows.Close()
				return fmt.Errorf("无法解密站点 %d 的自定义请求头: %w", id, err)
			}
			stored[i].Ciphertext, err = encryptUpstreamHeaderValue(stored[i].Name, value, authority, newHeaderKey)
			if err != nil {
				rows.Close()
				return fmt.Errorf("无法迁移站点 %d 的自定义请求头: %w", id, err)
			}
		}
		encoded, err := json.Marshal(stored)
		if err != nil {
			rows.Close()
			return err
		}
		updates = append(updates, update{id: id, raw: string(encoded)})
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range updates {
		if _, err := tx.Exec("UPDATE sites SET upstream_headers=? WHERE id=?", item.raw, item.id); err != nil {
			return err
		}
	}
	var telegramCiphertext string
	err = tx.QueryRow("SELECT bot_token_ciphertext FROM telegram_report_settings WHERE id=1").Scan(&telegramCiphertext)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if telegramCiphertext != "" {
		token, err := decryptTelegramBotTokenWithSecret(telegramCiphertext, oldCredentialKey)
		if err != nil {
			return fmt.Errorf("无法解密 Telegram Bot Token: %w", err)
		}
		migrated, err := encryptTelegramBotTokenWithSecret(token, newCredentialKey)
		if err != nil {
			return fmt.Errorf("无法迁移 Telegram Bot Token: %w", err)
		}
		if _, err := tx.Exec("UPDATE telegram_report_settings SET bot_token_ciphertext=? WHERE id=1", migrated); err != nil {
			return err
		}
	}
	hasACMEToken, err := backupSQLiteColumnExists(tx, "panel_settings", "acme_token_ciphertext")
	if err != nil {
		return err
	}
	if hasACMEToken {
		var acmeCiphertext string
		err = tx.QueryRow("SELECT acme_token_ciphertext FROM panel_settings WHERE id=1").Scan(&acmeCiphertext)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if acmeCiphertext != "" {
			token, err := decryptPanelACMETokenWithSecret(acmeCiphertext, oldCredentialKey)
			if err != nil {
				if _, currentErr := decryptPanelACMETokenWithSecret(acmeCiphertext, newCredentialKey); currentErr == nil {
					return tx.Commit()
				}
				return fmt.Errorf("无法解密 DNS API Token: %w", err)
			}
			migrated, err := encryptPanelACMETokenWithSecret(token, newCredentialKey)
			if err != nil {
				return fmt.Errorf("无法迁移 DNS API Token: %w", err)
			}
			if _, err := tx.Exec("UPDATE panel_settings SET acme_token_ciphertext=? WHERE id=1", migrated); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func backupSQLiteColumnExists(queryer interface {
	Query(string, ...any) (*sql.Rows, error)
}, tableName, columnName string) (bool, error) {
	rows, err := queryer.Query("PRAGMA table_info(" + tableName + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == columnName {
			return true, nil
		}
	}
	return false, rows.Err()
}

func backupHasTelegramToken(database []byte) (bool, error) {
	dir, err := os.MkdirTemp("", ".meridian-backup-check-*")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, backupDatabaseEntry)
	if err := writePrivateFileAtomic(path, database); err != nil {
		return false, err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return false, err
	}
	defer db.Close()
	var telegramCiphertext, acmeCiphertext string
	if exists, err := backupSQLiteColumnExists(db, "telegram_report_settings", "bot_token_ciphertext"); err != nil {
		return false, err
	} else if exists {
		if err := db.QueryRow("SELECT bot_token_ciphertext FROM telegram_report_settings WHERE id=1").Scan(&telegramCiphertext); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}
	if exists, err := backupSQLiteColumnExists(db, "panel_settings", "acme_token_ciphertext"); err != nil {
		return false, err
	} else if exists {
		if err := db.QueryRow("SELECT acme_token_ciphertext FROM panel_settings WHERE id=1").Scan(&acmeCiphertext); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}
	return telegramCiphertext != "" || acmeCiphertext != "", nil
}

func validateEphemeralRestoreCredentials(hasStoredCredentials bool, preservedPanelSettings *backupPanelSettings) error {
	if !jwtSecretEphemeral {
		return nil
	}
	if hasStoredCredentials || (preservedPanelSettings != nil && strings.TrimSpace(preservedPanelSettings.ACMETokenCiphertext) != "") {
		return errors.New("当前 JWT_SECRET 不是持久密钥，无法安全恢复 Telegram 或 ACME 凭据；请先配置稳定密钥")
	}
	return nil
}

func readBackupPanelSettings(db *sql.DB) (*backupPanelSettings, error) {
	if db == nil {
		return nil, errors.New("当前数据库不可用")
	}
	if err := ensureBackupPanelACMEColumns(db); err != nil {
		return nil, err
	}
	var settings backupPanelSettings
	err := db.QueryRow(`SELECT panel_domain, route_domain, listen_port, tls_enabled, configured,
		acme_email, acme_dns_provider, acme_token_ciphertext, acme_staging FROM panel_settings WHERE id=1`).Scan(
		&settings.PanelDomain, &settings.RouteDomain, &settings.ListenPort, &settings.TLSEnabled, &settings.Configured,
		&settings.ACMEEmail, &settings.ACMEDNSProvider, &settings.ACMETokenCiphertext, &settings.ACMEStaging,
	)
	if err != nil {
		return nil, err
	}
	return &settings, nil
}

func ensureBackupPanelACMEColumns(db *sql.DB) error {
	columns := []struct {
		name       string
		definition string
	}{
		{"acme_email", "TEXT NOT NULL DEFAULT ''"},
		{"acme_dns_provider", "TEXT NOT NULL DEFAULT 'cloudflare'"},
		{"acme_token_ciphertext", "TEXT NOT NULL DEFAULT ''"},
		{"acme_staging", "INTEGER NOT NULL DEFAULT 0"},
	}
	for _, column := range columns {
		exists, err := backupSQLiteColumnExists(db, "panel_settings", column.name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.Exec("ALTER TABLE panel_settings ADD COLUMN " + column.name + " " + column.definition); err != nil {
			return err
		}
	}
	return nil
}

func preserveBackupPanelSettings(path string, settings *backupPanelSettings) error {
	if settings == nil {
		return errors.New("缺少目标服务器 TLS 设置")
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	if err := ensureBackupPanelACMEColumns(db); err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE panel_settings SET panel_domain=?, route_domain=?, listen_port=?, tls_enabled=?, configured=?,
		acme_email=?, acme_dns_provider=?, acme_token_ciphertext=?, acme_staging=?, updated_at=CURRENT_TIMESTAMP WHERE id=1`,
		settings.PanelDomain, settings.RouteDomain, settings.ListenPort, settings.TLSEnabled, settings.Configured,
		settings.ACMEEmail, settings.ACMEDNSProvider, settings.ACMETokenCiphertext, settings.ACMEStaging)
	return err
}

func reconcileRestoredSiteIngress(path string, hostIngressAvailable bool) (int64, error) {
	if hostIngressAvailable {
		return 0, nil
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	result, err := db.Exec(`UPDATE sites SET public_host='', path_prefix='', ingress_mode=?, enabled=0, updated_at=CURRENT_TIMESTAMP WHERE ingress_mode IN (?, ?)`, ingressModeUnset, ingressModeHost, ingressModeBoth)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func writeRestorePending(dbPath string, manifest backupManifest, entries map[string][]byte, targetJWT, targetCredentialKey, targetHeaderKey []byte, preservedPanelSettings *backupPanelSettings, targetHostIngressWithoutTLS bool) (int64, error) {
	if dbPath == "" || dbPath == ":memory:" || strings.HasPrefix(dbPath, "file:") {
		return 0, errors.New("当前数据库模式不支持恢复")
	}
	oldJWT, err := base64.RawStdEncoding.DecodeString(manifest.JWTSecret)
	if err != nil || len(oldJWT) < 32 {
		return 0, errors.New("备份缺少有效的 JWT 密钥迁移信息")
	}
	oldCredentialKey := oldJWT
	if strings.TrimSpace(manifest.CredentialSecret) != "" {
		oldCredentialKey, err = base64.RawStdEncoding.DecodeString(manifest.CredentialSecret)
		if err != nil || len(oldCredentialKey) < 32 {
			return 0, errors.New("备份中的凭据加密密钥无效")
		}
	}
	oldHeaderKey, err := base64.RawStdEncoding.DecodeString(manifest.UpstreamHeaderKey)
	if err != nil {
		return 0, errors.New("备份中的上游请求头密钥无效")
	}
	pending := dbPath + backupPendingSuffix
	tmp, err := os.MkdirTemp(filepath.Dir(dbPath), ".meridian-restore-stage-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)
	databasePath := filepath.Join(tmp, backupDatabaseEntry)
	if err := writePrivateFileAtomic(databasePath, entries[backupDatabaseEntry]); err != nil {
		return 0, err
	}
	if err := validateSQLiteBackup(databasePath); err != nil {
		return 0, err
	}
	if !manifestIncludesTLS(manifest) {
		if err := preserveBackupPanelSettings(databasePath, preservedPanelSettings); err != nil {
			return 0, fmt.Errorf("保留目标服务器 TLS 设置: %w", err)
		}
	}
	stagedDB, err := sql.Open("sqlite", databasePath+"?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)")
	if err != nil {
		return 0, err
	}
	stagedPanelSettings, err := readBackupPanelSettings(stagedDB)
	_ = stagedDB.Close()
	if err != nil {
		return 0, fmt.Errorf("读取恢复后的面板设置: %w", err)
	}
	hostIngressAvailable := stagedPanelSettings.RouteDomain != "" && targetHostIngressWithoutTLS
	if stagedPanelSettings.RouteDomain != "" && stagedPanelSettings.TLSEnabled == 1 {
		if !manifestIncludesTLS(manifest) {
			hostIngressAvailable = true
		} else {
			_, hasCertificate := entries[backupTLSCertificate]
			_, hasPrivateKey := entries[backupTLSPrivateKey]
			if !hasCertificate || !hasPrivateKey {
				return 0, errors.New("备份启用了 TLS，但缺少证书或私钥")
			}
			hostIngressAvailable = true
		}
	}
	resetIngressCount, err := reconcileRestoredSiteIngress(databasePath, hostIngressAvailable)
	if err != nil {
		return 0, fmt.Errorf("迁移站点入口配置: %w", err)
	}
	if err := reencryptRestoredSecrets(databasePath, oldJWT, oldCredentialKey, oldHeaderKey, targetJWT, targetCredentialKey, targetHeaderKey); err != nil {
		return 0, err
	}
	if err := validateSQLiteBackup(databasePath); err != nil {
		return 0, err
	}
	for name, data := range entries {
		if !strings.HasPrefix(name, "tls/") {
			continue
		}
		if err := writePrivateFileAtomic(filepath.Join(tmp, filepath.FromSlash(name)), data); err != nil {
			return 0, err
		}
	}
	markerData, err := json.Marshal(restoreMarker{Files: manifest.Files, IncludeTLS: boolPointer(manifestIncludesTLS(manifest))})
	if err != nil {
		return 0, err
	}
	if err := writePrivateFileAtomic(filepath.Join(tmp, "restore.json"), markerData); err != nil {
		return 0, err
	}
	if err := os.RemoveAll(pending); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, pending); err != nil {
		return 0, err
	}
	return resetIngressCount, nil
}

func copyPrivateFile(source, target string) error {
	data, err := os.ReadFile(source) // #nosec G304 G703 -- source is always a path generated from the private restore directory and an allowlisted entry.
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(target, data)
}

func targetTLSPath(dbPath, entry string) string {
	certFile, keyFile := panelTLSPaths(dbPath)
	if certFile == "" {
		return ""
	}
	switch entry {
	case backupTLSCertificate:
		return certFile
	case backupTLSPrivateKey:
		return keyFile
	case backupTLSEnabled:
		return filepath.Join(filepath.Dir(certFile), "enabled")
	case backupACMEAccount:
		return filepath.Join(filepath.Dir(certFile), "acme-account.pem")
	case backupACMEAccountStaging:
		return filepath.Join(filepath.Dir(certFile), "acme-account-staging.pem")
	default:
		return ""
	}
}

func applyPendingRestore(dbPath string) (*restoreAppliedState, error) {
	if dbPath == "" || dbPath == ":memory:" || strings.HasPrefix(dbPath, "file:") {
		return nil, nil
	}
	pending := dbPath + backupPendingSuffix
	appliedMarker := dbPath + backupAppliedSuffix
	rollback := dbPath + backupRollbackSuffix
	if _, err := os.Stat(appliedMarker); err == nil { // #nosec G703 G304 -- all paths are derived from the administrator-controlled database path and fixed restore suffixes.
		if err := rollbackRestoreFiles(dbPath, rollback); err != nil {
			return nil, fmt.Errorf("回滚上次未完成的恢复: %w", err)
		}
		_ = os.Remove(appliedMarker) // #nosec G703 G304 -- fixed suffix path derived from the configured database path.
		_ = os.RemoveAll(rollback)   // #nosec G703 G304 -- fixed suffix path derived from the configured database path.
		// A crash after the staged database was moved leaves an incomplete
		// pending directory. The old installation is authoritative after the
		// rollback; discard that stage instead of trying to apply it again.
		_ = os.RemoveAll(pending) // #nosec G703 G304 -- fixed suffix path derived from the configured database path.
		return nil, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, err := os.Stat(pending); errors.Is(err, os.ErrNotExist) { // #nosec G703 -- pending is the fixed restore suffix derived from the configured database path.
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	markerData, err := os.ReadFile(filepath.Join(pending, "restore.json")) // #nosec G304 G703 -- pending is the fixed restore staging directory.
	if err != nil {
		return nil, fmt.Errorf("读取待恢复清单: %w", err)
	}
	var marker restoreMarker
	if err := json.Unmarshal(markerData, &marker); err != nil {
		return nil, fmt.Errorf("待恢复清单损坏: %w", err)
	}
	if err := os.RemoveAll(rollback); err != nil { // #nosec G703 G304 -- fixed rollback suffix path.
		return nil, err
	}
	if err := os.MkdirAll(rollback, 0o700); err != nil { // #nosec G703 G304 -- fixed rollback suffix path.
		return nil, err
	}
	rollbackReady := false
	committed := false
	defer func() {
		if rollbackReady && !committed {
			_ = rollbackRestoreFiles(dbPath, rollback)
			_ = os.Remove(dbPath + backupAppliedSuffix) // #nosec G703 G304 -- fixed restore marker suffix.
			_ = os.RemoveAll(rollback)                  // #nosec G703 G304 -- fixed rollback suffix path.
			_ = os.RemoveAll(pending)                   // #nosec G703 G304 -- fixed pending suffix path.
		}
	}()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		source := dbPath + suffix
		if _, err := os.Stat(source); err == nil { // #nosec G703 G304 -- source is the configured database path plus a fixed SQLite suffix.
			if err := copyPrivateFile(source, filepath.Join(rollback, backupDatabaseEntry+suffix)); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	// Persist the scope before the first destructive action. If startup is
	// interrupted later, automatic rollback must know whether TLS participated.
	if err := writePrivateFileAtomic(filepath.Join(rollback, "restore.json"), markerData); err != nil { // #nosec G703 G304 -- rollback is the fixed restore directory.
		return nil, err
	}
	rollbackReady = true
	if markerIncludesTLS(marker) {
		for entry := range backupAllowedEntries {
			if !strings.HasPrefix(entry, "tls/") {
				continue
			}
			target := targetTLSPath(dbPath, entry)
			if target == "" {
				continue
			}
			if _, err := os.Stat(target); err == nil { // #nosec G703 G304 -- target is derived from the fixed TLS allowlist.
				if err := copyPrivateFile(target, filepath.Join(rollback, filepath.FromSlash(entry))); err != nil {
					return nil, err
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
	}
	// From this point on every destructive change is recoverable. The marker is
	// written before replacing live files so a process interruption at any later
	// instruction causes the next startup to restore the complete old snapshot.
	if err := writePrivateFileAtomic(appliedMarker, []byte("pending validation\n")); err != nil { // #nosec G703 G304 -- fixed restore marker suffix.
		return nil, err
	}
	if markerIncludesTLS(marker) {
		for entry := range backupAllowedEntries {
			if !strings.HasPrefix(entry, "tls/") {
				continue
			}
			target := targetTLSPath(dbPath, entry)
			if target != "" {
				if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) { // #nosec G703 G304 -- target is derived from the fixed TLS allowlist.
					return nil, err
				}
			}
		}
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) { // #nosec G703 G304 -- fixed SQLite sidecar suffix.
			return nil, err
		}
	}
	if err := os.Rename(filepath.Join(pending, backupDatabaseEntry), dbPath); err != nil { // #nosec G703 G304 -- source is the fixed database archive entry in pending.
		return nil, err
	}
	if markerIncludesTLS(marker) {
		for _, entry := range marker.Files {
			if !strings.HasPrefix(entry, "tls/") {
				continue
			}
			target := targetTLSPath(dbPath, entry)
			if target == "" {
				continue
			}
			if err := copyPrivateFile(filepath.Join(pending, filepath.FromSlash(entry)), target); err != nil { // #nosec G703 G304 -- entry is allowlisted and target is a fixed TLS path.
				return nil, err
			}
		}
	}
	if err := os.RemoveAll(pending); err != nil { // #nosec G703 G304 -- fixed pending suffix path.
		return nil, err
	}
	committed = true
	return &restoreAppliedState{RollbackDir: rollback}, nil
}

func rollbackRestoreFiles(dbPath, rollback string) error {
	if rollback == "" {
		return errors.New("恢复回滚目录为空")
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(dbPath + suffix) // #nosec G703 G304 -- fixed SQLite sidecar suffix.
		source := filepath.Join(rollback, backupDatabaseEntry+suffix)
		if _, err := os.Stat(source); err == nil { // #nosec G703 G304 -- source is the fixed rollback database entry.
			if err := os.Rename(source, dbPath+suffix); err != nil {
				return err
			}
		} else if suffix == "" {
			return errors.New("恢复回滚副本缺少数据库")
		}
	}
	if restoreDirectoryIncludesTLS(rollback) {
		for entry := range backupAllowedEntries {
			if !strings.HasPrefix(entry, "tls/") {
				continue
			}
			target := targetTLSPath(dbPath, entry)
			if target == "" {
				continue
			}
			_ = os.Remove(target) // #nosec G703 G304 -- target is derived from the fixed TLS allowlist.
			source := filepath.Join(rollback, filepath.FromSlash(entry))
			if _, err := os.Stat(source); err == nil { // #nosec G703 G304 -- source is an allowlisted rollback TLS entry.
				if err := copyPrivateFile(source, target); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func rollbackAppliedRestore(dbPath string, state *restoreAppliedState) error {
	if state == nil {
		return nil
	}
	if err := rollbackRestoreFiles(dbPath, state.RollbackDir); err != nil {
		return err
	}
	_ = os.Remove(dbPath + backupAppliedSuffix) // #nosec G703 G304 -- fixed restore marker suffix.
	return os.RemoveAll(state.RollbackDir)      // #nosec G703 G304 -- rollback directory was created by Meridian.
}

func finalizeAppliedRestore(dbPath string) error {
	if err := os.Remove(dbPath + backupAppliedSuffix); err != nil && !errors.Is(err, os.ErrNotExist) { // #nosec G703 G304 -- fixed restore marker suffix.
		return err
	}
	return os.RemoveAll(dbPath + backupRollbackSuffix) // #nosec G703 G304 -- fixed rollback suffix path.
}

func (a *App) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request struct {
		Password   string `json:"password"`
		IncludeTLS *bool  `json:"include_tls"`
	}
	if err := decodeJSONBody(w, r, &request); err != nil {
		a.jsonErr(w, http.StatusBadRequest, "请求格式无效")
		return
	}
	a.backupMu.Lock()
	defer a.backupMu.Unlock()
	includeTLS := false
	if request.IncludeTLS != nil {
		includeTLS = *request.IncludeTLS
	}
	payload, err := a.buildBackup(request.Password, includeTLS)
	if err != nil {
		a.jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="meridian-backup-%s.mrbak"`, time.Now().Format("20060102-150405")))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (a *App) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if a.dbPath == "" || a.dbPath == ":memory:" || strings.HasPrefix(a.dbPath, "file:") {
		a.jsonErr(w, http.StatusConflict, "当前数据库模式不支持恢复")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, backupMaxUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		a.jsonErr(w, http.StatusBadRequest, "上传文件过大或表单无效")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	password := r.FormValue("password")
	if r.FormValue("confirm") != "恢复" {
		a.jsonErr(w, http.StatusBadRequest, "请输入“恢复”确认操作")
		return
	}
	file, _, err := r.FormFile("backup")
	if err != nil {
		a.jsonErr(w, http.StatusBadRequest, "请选择 Meridian 备份文件")
		return
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, backupMaxUploadBytes+1))
	if err != nil || len(payload) > backupMaxUploadBytes {
		a.jsonErr(w, http.StatusBadRequest, "备份文件读取失败或超过 256 MiB")
		return
	}
	a.backupMu.Lock()
	defer a.backupMu.Unlock()
	plain, err := openBackup(payload, password)
	if err != nil {
		a.jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	manifest, entries, err := parseBackupArchive(plain)
	if err != nil {
		a.jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hasStoredCredentials := false
	if jwtSecretEphemeral {
		var tokenErr error
		hasStoredCredentials, tokenErr = backupHasTelegramToken(entries[backupDatabaseEntry])
		if tokenErr != nil {
			a.jsonErr(w, http.StatusBadRequest, "恢复校验失败：无法检查已保存凭据")
			return
		}
	}
	targetHeaderKey := []byte(nil)
	if a.pm != nil {
		targetHeaderKey = a.pm.upstreamHeaderKey
	}
	if len(targetHeaderKey) != 32 {
		oldHeaderKey, keyErr := base64.RawStdEncoding.DecodeString(manifest.UpstreamHeaderKey)
		if keyErr != nil {
			a.jsonErr(w, http.StatusBadRequest, "恢复校验失败：备份中的上游请求头密钥无效")
			return
		}
		if len(oldHeaderKey) == 32 {
			tempDir, tempErr := os.MkdirTemp("", ".meridian-header-check-*")
			if tempErr != nil {
				a.jsonErr(w, http.StatusInternalServerError, "恢复校验失败")
				return
			}
			tempDB := filepath.Join(tempDir, backupDatabaseEntry)
			writeErr := writePrivateFileAtomic(tempDB, entries[backupDatabaseEntry])
			hasHeaders := false
			if writeErr == nil {
				checkDB, openErr := sql.Open("sqlite", "file:"+filepath.ToSlash(tempDB)+"?mode=ro&_pragma=query_only(1)")
				if openErr == nil {
					var count int
					writeErr = checkDB.QueryRow("SELECT COUNT(*) FROM sites WHERE upstream_headers <> '' AND upstream_headers <> '[]'").Scan(&count)
					hasHeaders = count > 0
					_ = checkDB.Close()
				} else {
					writeErr = openErr
				}
			}
			_ = os.RemoveAll(tempDir)
			if writeErr != nil {
				a.jsonErr(w, http.StatusBadRequest, "恢复校验失败：无法检查自定义上游请求头")
				return
			}
			if hasHeaders {
				a.jsonErr(w, http.StatusConflict, "当前 UPSTREAM_HEADER_KEY 未配置，无法安全恢复自定义上游请求头")
				return
			}
		}
	}
	var preservedPanelSettings *backupPanelSettings
	if !manifestIncludesTLS(manifest) {
		preservedPanelSettings, err = readBackupPanelSettings(a.db.db)
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "恢复校验失败：无法读取当前 TLS 设置")
			return
		}
	}
	if err := validateEphemeralRestoreCredentials(hasStoredCredentials, preservedPanelSettings); err != nil {
		a.jsonErr(w, http.StatusConflict, err.Error())
		return
	}
	targetHostIngressWithoutTLS := a.panelBindLoopback || len(a.trustedProxies) > 0
	resetIngressCount, err := writeRestorePending(a.dbPath, manifest, entries, jwtSecret, activeStoredCredentialSecret(), targetHeaderKey, preservedPanelSettings, targetHostIngressWithoutTLS)
	if err != nil {
		a.jsonErr(w, http.StatusBadRequest, "恢复校验失败："+err.Error())
		return
	}
	a.clearSessionCookie(w, r)
	message := "备份已通过校验，Meridian 正在重启并应用恢复数据"
	if resetIngressCount > 0 {
		message += fmt.Sprintf("；%d 个站点的原入口不适用于当前服务器，已保留站点、清空入口并停用，请恢复后编辑入口再启用", resetIngressCount)
	}
	a.jsonOK(w, map[string]interface{}{
		"restarting":          true,
		"message":             message,
		"ingress_reset_count": resetIngressCount,
	})
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	if a.restartCh != nil {
		a.restartOnce.Do(func() {
			time.AfterFunc(500*time.Millisecond, func() { close(a.restartCh) })
		})
	}
}
