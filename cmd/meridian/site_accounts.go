package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/publicsuffix"
)

const siteAccountCipherPrefix = "v1:"

type SiteAccount struct {
	ID            int64  `json:"id"`
	SiteID        int64  `json:"site_id"`
	SiteName      string `json:"site_name,omitempty"`
	AccountName   string `json:"account_name"`
	Username      string `json:"username"`
	ExpiresAt     string `json:"expires_at"`
	Note          string `json:"note"`
	ReminderDays  *int   `json:"reminder_days"`
	PasswordSet   bool   `json:"password_configured"`
	SecuritySet   bool   `json:"security_password_configured"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
	Lifecycle     string `json:"lifecycle"`
	Status        string `json:"status"`
	DaysLeft      int    `json:"days_left,omitempty"`
	RenewalCount  int    `json:"renewal_count,omitempty"`
	LastRenewedAt string `json:"last_renewed_at,omitempty"`
}

// accountLifecycleState is derived from the expiry value so old databases and
// imported records do not need a destructive status migration.
func accountLifecycleState(expiresAt string, reminderDays *int, now time.Time, location *time.Location) (string, int) {
	if strings.TrimSpace(expiresAt) == "" {
		return "active", 0
	}
	expires, err := parseSiteAccountExpiryInLocation(expiresAt, location)
	if err != nil {
		return "unknown", 0
	}
	days := int(math.Ceil(expires.Sub(now).Hours() / 24))
	if expires.Before(now) {
		days = int(math.Floor(expires.Sub(now).Hours() / 24))
		return "expired", days
	}
	if reminderDays != nil && now.After(expires.AddDate(0, 0, -*reminderDays)) {
		return "expiring", days
	}
	return "active", days
}

type storedSiteAccount struct {
	SiteAccount
	PasswordCiphertext         string
	SecurityPasswordCiphertext string
}

type SiteAccountInput struct {
	AccountName      string `json:"account_name"`
	Username         string `json:"username"`
	Password         string `json:"password,omitempty"`          // #nosec G117 -- explicitly authorized account memo/export.
	SecurityPassword string `json:"security_password,omitempty"` // #nosec G117 -- explicitly authorized account memo/export.
	ExpiresAt        string `json:"expires_at"`
	Note             string `json:"note"`
	ReminderDays     *int   `json:"reminder_days,omitempty"`
	ClearReminder    bool   `json:"clear_reminder,omitempty"`
	ClearNote        bool   `json:"clear_note,omitempty"`
	ClearPassword    bool   `json:"clear_password,omitempty"`
	ClearSecurity    bool   `json:"clear_security_password,omitempty"`
	ClearExpiry      bool   `json:"clear_expires_at,omitempty"`
}

func siteAccountKey(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

func validateNewSiteAccounts(accounts []SiteAccountInput) error {
	if len(accounts) > 500 {
		return errors.New("单个站点最多一次添加 500 个账号")
	}
	seen := make(map[string]bool, len(accounts))
	for i, input := range accounts {
		account, err := normalizeSiteAccountInput(input, nil)
		if err != nil {
			return fmt.Errorf("第 %d 个账号需要调整：%w", i+1, err)
		}
		if seen[account.Username] {
			return errors.New("同一站点中用户名重复")
		}
		seen[account.Username] = true
	}
	return nil
}

func encryptSiteAccountSecret(value string) (string, error) {
	return encryptSiteAccountSecretWithSecret(value, activeStoredCredentialSecret())
}

func encryptSiteAccountSecretWithSecret(value string, secret []byte) (string, error) {
	if value == "" {
		return "", nil
	}
	block, err := aes.NewCipher(siteAccountKey(secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate account secret nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, []byte(value), []byte("meridian-site-account:v1"))
	return siteAccountCipherPrefix + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func decryptSiteAccountSecret(ciphertext string) (string, error) {
	return decryptSiteAccountSecretWithSecrets(ciphertext, storedCredentialSecrets())
}

func decryptSiteAccountSecretWithSecrets(ciphertext string, secrets [][]byte) (string, error) {
	if strings.TrimSpace(ciphertext) == "" {
		return "", nil
	}
	if !strings.HasPrefix(ciphertext, siteAccountCipherPrefix) {
		return "", errors.New("invalid account secret ciphertext")
	}
	encoded := strings.TrimPrefix(ciphertext, siteAccountCipherPrefix)
	payload, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return "", errors.New("invalid account secret ciphertext")
	}
	for _, secret := range secrets {
		block, blockErr := aes.NewCipher(siteAccountKey(secret))
		if blockErr != nil {
			continue
		}
		gcm, gcmErr := cipher.NewGCM(block)
		if gcmErr != nil || len(payload) < gcm.NonceSize()+gcm.Overhead() {
			continue
		}
		plain, openErr := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], []byte("meridian-site-account:v1"))
		if openErr == nil {
			return string(plain), nil
		}
	}
	return "", errors.New("unable to decrypt account secret")
}

func normalizeSiteAccountInput(input SiteAccountInput, existing *storedSiteAccount) (SiteAccountInput, error) {
	input.AccountName = strings.TrimSpace(input.AccountName)
	input.Username = strings.TrimSpace(input.Username)
	// Passwords are opaque values. Preserve intentional leading/trailing spaces.
	input.ExpiresAt = strings.TrimSpace(input.ExpiresAt)
	input.Note = strings.TrimSpace(input.Note)
	if input.ReminderDays != nil && (*input.ReminderDays < 0 || *input.ReminderDays > 3650) {
		return SiteAccountInput{}, errors.New("提前提醒天数应为 0–3650，0 表示到期时提醒")
	}
	if input.ExpiresAt != "" {
		if len(input.ExpiresAt) > 64 {
			return SiteAccountInput{}, errors.New("到期时间过长")
		}
		if _, err := parseSiteAccountExpiry(input.ExpiresAt); err != nil {
			return SiteAccountInput{}, errors.New("到期时间格式应为日期、ISO 时间或常见日期时间")
		}
	}
	if existing != nil {
		if input.AccountName == "" {
			input.AccountName = existing.AccountName
		}
		if input.Username == "" {
			input.Username = existing.Username
		}
		if input.ExpiresAt == "" && !input.ClearExpiry {
			input.ExpiresAt = existing.ExpiresAt
		}
		if input.Note == "" && !input.ClearNote {
			input.Note = existing.Note
		}
		if input.ReminderDays == nil && !input.ClearReminder {
			input.ReminderDays = existing.ReminderDays
		}
	}
	if input.AccountName == "" && input.Username != "" {
		input.AccountName = input.Username
	}
	if input.Username == "" && input.AccountName != "" {
		input.Username = input.AccountName
	}
	if input.AccountName == "" || input.Username == "" {
		return SiteAccountInput{}, errors.New("填写账号信息时，账号名称和用户名至少需要一个")
	}
	if len(input.AccountName) > 128 || len(input.Username) > 128 || len(input.Note) > 2000 {
		return SiteAccountInput{}, errors.New("账号名称、用户名或备注过长")
	}
	return input, nil
}

func parseSiteAccountExpiry(value string) (time.Time, error) {
	return parseSiteAccountExpiryInLocation(value, time.UTC)
}

// formatSiteAccountExpiryDate keeps account expiry values readable anywhere a
// user sees them. The stored value may include a time and fractional seconds
// for reminder/renewal calculations, but the account UI only needs the date.
func formatSiteAccountExpiryDate(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) >= len("2006-01-02") {
		date := value[:len("2006-01-02")]
		if _, err := time.Parse("2006-01-02", date); err == nil {
			return date
		}
	}
	if parsed, err := parseSiteAccountExpiry(value); err == nil {
		return parsed.Format("2006-01-02")
	}
	// Keep malformed legacy values visible so an administrator can correct them.
	return value
}

func (d *DB) parseSiteAccountExpiry(value string) (time.Time, error) {
	settings := d.currentSystemSettings()
	return parseSiteAccountExpiryInLocation(value, timezoneLocationByName(settings.ScheduleTimezoneName, settings.ScheduleTimezone))
}

func parseSiteAccountExpiryInLocation(value string, location *time.Location) (time.Time, error) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{
		"2006-01-02",
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
	} {
		parsed, err := time.ParseInLocation(layout, value, location)
		if err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, errors.New("invalid account expiry")
}

func (d *DB) listSiteAccounts(siteID int64) ([]storedSiteAccount, error) {
	rows, err := d.db.Query(`SELECT id, site_id, account_name, username, password_ciphertext, security_password_ciphertext, expires_at, note, reminder_days, created_at, updated_at FROM site_accounts WHERE site_id=? ORDER BY id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []storedSiteAccount
	for rows.Next() {
		var item storedSiteAccount
		if err := rows.Scan(&item.ID, &item.SiteID, &item.AccountName, &item.Username, &item.PasswordCiphertext, &item.SecurityPasswordCiphertext, &item.ExpiresAt, &item.Note, &item.ReminderDays, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.PasswordSet = item.PasswordCiphertext != ""
		item.SecuritySet = item.SecurityPasswordCiphertext != ""
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if result == nil {
		result = []storedSiteAccount{}
	}
	return result, nil
}

func publicSiteAccount(item storedSiteAccount, siteName string) SiteAccount {
	item.SiteAccount.SiteName = siteName
	item.SiteAccount.PasswordSet = item.PasswordCiphertext != ""
	item.SiteAccount.SecuritySet = item.SecurityPasswordCiphertext != ""
	item.SiteAccount.Lifecycle, item.SiteAccount.DaysLeft = accountLifecycleState(item.ExpiresAt, item.ReminderDays, time.Now(), time.Local)
	item.SiteAccount.Status = item.SiteAccount.Lifecycle
	return item.SiteAccount
}

func (d *DB) decorateSiteAccount(item storedSiteAccount, siteName string) SiteAccount {
	result := publicSiteAccount(item, siteName)
	settings := d.currentSystemSettings()
	location := timezoneLocationByName(settings.ScheduleTimezoneName, settings.ScheduleTimezone)
	result.Lifecycle, result.DaysLeft = accountLifecycleState(item.ExpiresAt, item.ReminderDays, time.Now().In(location), location)
	result.Status = result.Lifecycle
	_ = d.db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(renewed_at), '') FROM account_renewals WHERE account_id=?`, item.ID).Scan(&result.RenewalCount, &result.LastRenewedAt)
	return result
}

type siteAccountStore interface {
	Exec(string, ...any) (sql.Result, error)
	QueryRow(string, ...any) *sql.Row
}

func (d *DB) getSiteAccount(siteID, accountID int64) (*storedSiteAccount, error) {
	return getSiteAccountFrom(d.db, siteID, accountID)
}

func (d *DB) getSiteAccountByID(accountID int64) (*storedSiteAccount, error) {
	var item storedSiteAccount
	err := d.db.QueryRow(`SELECT id, site_id, account_name, username, password_ciphertext, security_password_ciphertext, expires_at, note, reminder_days, created_at, updated_at FROM site_accounts WHERE id=?`, accountID).Scan(&item.ID, &item.SiteID, &item.AccountName, &item.Username, &item.PasswordCiphertext, &item.SecurityPasswordCiphertext, &item.ExpiresAt, &item.Note, &item.ReminderDays, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return nil, err
	}
	item.PasswordSet = item.PasswordCiphertext != ""
	item.SecuritySet = item.SecurityPasswordCiphertext != ""
	return &item, nil
}

func getSiteAccountFrom(store siteAccountStore, siteID, accountID int64) (*storedSiteAccount, error) {
	var item storedSiteAccount
	err := store.QueryRow(`SELECT id, site_id, account_name, username, password_ciphertext, security_password_ciphertext, expires_at, note, reminder_days, created_at, updated_at FROM site_accounts WHERE site_id=? AND id=?`, siteID, accountID).Scan(&item.ID, &item.SiteID, &item.AccountName, &item.Username, &item.PasswordCiphertext, &item.SecurityPasswordCiphertext, &item.ExpiresAt, &item.Note, &item.ReminderDays, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return nil, err
	}
	item.PasswordSet = item.PasswordCiphertext != ""
	item.SecuritySet = item.SecurityPasswordCiphertext != ""
	return &item, nil
}

func (d *DB) saveSiteAccount(siteID int64, accountID int64, input SiteAccountInput) (*storedSiteAccount, error) {
	// Read, merge and write on the same transaction. Partial edits must not
	// overwrite another writer's fields between the read and the update.
	tx, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	item, err := saveSiteAccountIn(tx, siteID, accountID, input)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return item, nil
}

func saveSiteAccountIn(store siteAccountStore, siteID int64, accountID int64, input SiteAccountInput) (*storedSiteAccount, error) {
	var existing *storedSiteAccount
	var err error
	if accountID > 0 {
		existing, err = getSiteAccountFrom(store, siteID, accountID)
		if err != nil {
			return nil, err
		}
	}
	input, err = normalizeSiteAccountInput(input, existing)
	if err != nil {
		return nil, err
	}
	passwordCipher := ""
	securityCipher := ""
	if existing != nil {
		passwordCipher, securityCipher = existing.PasswordCiphertext, existing.SecurityPasswordCiphertext
	}
	if existing == nil || input.Password != "" || input.ClearPassword {
		passwordCipher, err = encryptSiteAccountSecret(input.Password)
		if err != nil {
			return nil, err
		}
	}
	if existing == nil || input.SecurityPassword != "" || input.ClearSecurity {
		securityCipher, err = encryptSiteAccountSecret(input.SecurityPassword)
		if err != nil {
			return nil, err
		}
	}
	if accountID == 0 {
		result, err := store.Exec(`INSERT INTO site_accounts (site_id, account_name, username, password_ciphertext, security_password_ciphertext, expires_at, note, reminder_days) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, siteID, input.AccountName, input.Username, passwordCipher, securityCipher, input.ExpiresAt, input.Note, input.ReminderDays)
		if err != nil {
			return nil, err
		}
		accountID, err = result.LastInsertId()
		if err != nil {
			return nil, err
		}
	} else {
		_, err = store.Exec(`UPDATE site_accounts SET account_name=?, username=?, password_ciphertext=?, security_password_ciphertext=?, expires_at=?, note=?, reminder_days=?, updated_at=CURRENT_TIMESTAMP WHERE site_id=? AND id=?`, input.AccountName, input.Username, passwordCipher, securityCipher, input.ExpiresAt, input.Note, input.ReminderDays, siteID, accountID)
		if err != nil {
			return nil, err
		}
	}
	return getSiteAccountFrom(store, siteID, accountID)
}

func accountPlaintext(item storedSiteAccount) (SiteAccountInput, error) {
	password, err := decryptSiteAccountSecret(item.PasswordCiphertext)
	if err != nil {
		return SiteAccountInput{}, err
	}
	security, err := decryptSiteAccountSecret(item.SecurityPasswordCiphertext)
	if err != nil {
		return SiteAccountInput{}, err
	}
	return SiteAccountInput{AccountName: item.AccountName, Username: item.Username, Password: password, SecurityPassword: security, ExpiresAt: item.ExpiresAt, Note: item.Note, ReminderDays: item.ReminderDays}, nil
}

// Only the authenticated account workspace returns cleartext memo fields.
// Reminder/status responses continue to use publicSiteAccount metadata.
type siteAccountMemo struct {
	SiteAccount
	Password         string `json:"password"`          // #nosec G117 -- authorized memo response.
	SecurityPassword string `json:"security_password"` // #nosec G117 -- authorized memo response.
}

type accountRenewal struct {
	ID                int64  `json:"id"`
	AccountID         int64  `json:"account_id"`
	PreviousExpiresAt string `json:"previous_expires_at"`
	NewExpiresAt      string `json:"new_expires_at"`
	DurationDays      int    `json:"duration_days"`
	RenewedAt         string `json:"renewed_at"`
	Note              string `json:"note,omitempty"`
}

type accountReminderRecord struct {
	AccountID    int64  `json:"account_id"`
	SiteID       int64  `json:"site_id"`
	SiteName     string `json:"site_name"`
	AccountName  string `json:"account_name"`
	ExpiresAt    string `json:"expires_at"`
	ReminderDays int    `json:"reminder_days"`
	ChatID       int64  `json:"chat_id"`
	SentAt       string `json:"sent_at"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	AttemptedAt  string `json:"attempted_at"`
	Action       string `json:"action,omitempty"`
	SnoozedUntil string `json:"snoozed_until,omitempty"`
}

func (d *DB) accountReminderAction(accountID int64, expiresAt string, reminderDays int) (status, snoozedUntil string, err error) {
	err = d.db.QueryRow(`SELECT status, snoozed_until FROM account_reminder_actions WHERE account_id=? AND expires_at=? AND reminder_days=?`, accountID, expiresAt, reminderDays).Scan(&status, &snoozedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return status, snoozedUntil, err
}

func (d *DB) saveAccountReminderAction(accountID int64, expiresAt string, reminderDays int, status string, snoozedUntil time.Time, note string) error {
	if status != "handled" && status != "ignored" && status != "snoozed" {
		return errors.New("invalid reminder action")
	}
	if accountID <= 0 || strings.TrimSpace(expiresAt) == "" || reminderDays < 0 || reminderDays > 3650 {
		return errors.New("invalid reminder action target")
	}
	if status != "snoozed" {
		snoozedUntil = time.Time{}
	} else if snoozedUntil.IsZero() {
		snoozedUntil = time.Now().Add(24 * time.Hour)
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO account_reminder_actions(account_id, expires_at, reminder_days, status, snoozed_until, note, acted_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(account_id, expires_at, reminder_days) DO UPDATE SET status=excluded.status, snoozed_until=excluded.snoozed_until, note=excluded.note, acted_at=CURRENT_TIMESTAMP`, accountID, expiresAt, reminderDays, status, func() string {
		if snoozedUntil.IsZero() {
			return ""
		}
		return snoozedUntil.UTC().Format(time.RFC3339)
	}(), strings.TrimSpace(note))
	if err != nil {
		return err
	}
	if status == "snoozed" {
		// Preserve legacy receipts in the history before rearming delivery.
		if _, err := tx.Exec(`INSERT INTO account_reminder_attempts(account_id, expires_at, reminder_days, chat_id, status, attempted_at) SELECT d.account_id, d.expires_at, d.reminder_days, d.chat_id, 'sent', d.sent_at FROM account_reminder_deliveries d WHERE d.account_id=? AND d.expires_at=? AND d.reminder_days=? AND NOT EXISTS (SELECT 1 FROM account_reminder_attempts t WHERE t.account_id=d.account_id AND t.expires_at=d.expires_at AND t.reminder_days=d.reminder_days AND t.chat_id=d.chat_id AND t.status='sent')`, accountID, expiresAt, reminderDays); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM account_reminder_deliveries WHERE account_id=? AND expires_at=? AND reminder_days=?`, accountID, expiresAt, reminderDays); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) recordAccountReminderAttempt(accountID int64, expiresAt string, reminderDays int, chatID int64, status, deliveryError string) error {
	if status != "sent" && status != "failed" {
		return errors.New("invalid reminder delivery status")
	}
	if len(deliveryError) > 512 {
		deliveryError = deliveryError[:512]
	}
	_, err := d.db.Exec(`INSERT INTO account_reminder_attempts(account_id, expires_at, reminder_days, chat_id, status, error) VALUES(?,?,?,?,?,?)`, accountID, expiresAt, reminderDays, chatID, status, deliveryError)
	return err
}

func (d *DB) recordAccountReminderSent(accountID int64, expiresAt string, reminderDays int, chatID int64) error {
	if err := d.recordAccountReminderAttempt(accountID, expiresAt, reminderDays, chatID, "sent", ""); err != nil {
		return err
	}
	_, err := d.db.Exec(`INSERT OR IGNORE INTO account_reminder_deliveries(account_id, expires_at, reminder_days, chat_id) VALUES(?,?,?,?)`, accountID, expiresAt, reminderDays, chatID)
	return err
}

func (d *DB) renewSiteAccount(siteID, accountID int64, days int, note string) (*storedSiteAccount, accountRenewal, error) {
	if days < 1 || days > 3650 {
		return nil, accountRenewal{}, errors.New("续期天数应为 1–3650")
	}
	tx, err := d.db.Begin()
	if err != nil {
		return nil, accountRenewal{}, err
	}
	defer tx.Rollback()
	item, err := getSiteAccountFrom(tx, siteID, accountID)
	if err != nil {
		return nil, accountRenewal{}, err
	}
	settings := d.currentSystemSettings()
	location := timezoneLocationByName(settings.ScheduleTimezoneName, settings.ScheduleTimezone)
	now := time.Now().In(location)
	base := now
	if item.ExpiresAt != "" {
		if parsed, parseErr := parseSiteAccountExpiryInLocation(item.ExpiresAt, location); parseErr == nil && parsed.After(base) {
			base = parsed
		}
	}
	newExpiry := base.AddDate(0, 0, days)
	formatted := newExpiry.Format(time.RFC3339)
	if len(strings.TrimSpace(item.ExpiresAt)) == len("2006-01-02") {
		formatted = newExpiry.Format("2006-01-02")
	}
	if _, err := tx.Exec(`UPDATE site_accounts SET expires_at=?, updated_at=CURRENT_TIMESTAMP WHERE site_id=? AND id=?`, formatted, siteID, accountID); err != nil {
		return nil, accountRenewal{}, err
	}
	result, err := tx.Exec(`INSERT INTO account_renewals(account_id, previous_expires_at, new_expires_at, duration_days, note) VALUES(?,?,?,?,?)`, accountID, item.ExpiresAt, formatted, days, strings.TrimSpace(note))
	if err != nil {
		return nil, accountRenewal{}, err
	}
	renewalID, err := result.LastInsertId()
	if err != nil {
		return nil, accountRenewal{}, err
	}
	if err := tx.Commit(); err != nil {
		return nil, accountRenewal{}, err
	}
	updated, err := d.getSiteAccount(siteID, accountID)
	if err != nil {
		return nil, accountRenewal{}, err
	}
	return updated, accountRenewal{ID: renewalID, AccountID: accountID, PreviousExpiresAt: item.ExpiresAt, NewExpiresAt: formatted, DurationDays: days, RenewedAt: time.Now().UTC().Format(time.RFC3339), Note: strings.TrimSpace(note)}, nil
}

func (d *DB) listAccountRenewals(siteID, accountID int64) ([]accountRenewal, error) {
	rows, err := d.db.Query(`SELECT r.id, r.account_id, r.previous_expires_at, r.new_expires_at, r.duration_days, r.renewed_at, r.note FROM account_renewals r JOIN site_accounts a ON a.id=r.account_id WHERE a.site_id=? AND r.account_id=? ORDER BY r.id DESC`, siteID, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]accountRenewal, 0)
	for rows.Next() {
		var item accountRenewal
		if err := rows.Scan(&item.ID, &item.AccountID, &item.PreviousExpiresAt, &item.NewExpiresAt, &item.DurationDays, &item.RenewedAt, &item.Note); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (d *DB) listAccountReminderRecords(siteID, accountID int64) ([]accountReminderRecord, error) {
	query := `SELECT * FROM (SELECT t.account_id, a.site_id, s.name, a.account_name, t.expires_at, t.reminder_days, t.chat_id, CASE WHEN t.status='sent' THEN t.attempted_at ELSE '' END, t.status, t.error, t.attempted_at, COALESCE(x.status, ''), COALESCE(x.snoozed_until, '') FROM account_reminder_attempts t JOIN site_accounts a ON a.id=t.account_id JOIN sites s ON s.id=a.site_id LEFT JOIN account_reminder_actions x ON x.account_id=t.account_id AND x.expires_at=t.expires_at AND x.reminder_days=t.reminder_days WHERE 1=1`
	args := make([]any, 0, 2)
	if siteID > 0 {
		query += " AND a.site_id=?"
		args = append(args, siteID)
	}
	if accountID > 0 {
		query += " AND t.account_id=?"
		args = append(args, accountID)
	}
	query += ` UNION ALL SELECT d.account_id, a.site_id, s.name, a.account_name, d.expires_at, d.reminder_days, d.chat_id, d.sent_at, 'sent', '', d.sent_at, COALESCE(x.status, ''), COALESCE(x.snoozed_until, '') FROM account_reminder_deliveries d JOIN site_accounts a ON a.id=d.account_id JOIN sites s ON s.id=a.site_id LEFT JOIN account_reminder_actions x ON x.account_id=d.account_id AND x.expires_at=d.expires_at AND x.reminder_days=d.reminder_days WHERE NOT EXISTS (SELECT 1 FROM account_reminder_attempts t WHERE t.account_id=d.account_id AND t.expires_at=d.expires_at AND t.reminder_days=d.reminder_days AND t.chat_id=d.chat_id AND t.status='sent')`
	if siteID > 0 {
		query += " AND a.site_id=?"
		args = append(args, siteID)
	}
	if accountID > 0 {
		query += " AND d.account_id=?"
		args = append(args, accountID)
	}
	query += ") ORDER BY attempted_at DESC, account_id DESC"
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]accountReminderRecord, 0)
	for rows.Next() {
		var item accountReminderRecord
		if err := rows.Scan(&item.AccountID, &item.SiteID, &item.SiteName, &item.AccountName, &item.ExpiresAt, &item.ReminderDays, &item.ChatID, &item.SentAt, &item.Status, &item.Error, &item.AttemptedAt, &item.Action, &item.SnoozedUntil); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func accountMemo(item storedSiteAccount, name string) (siteAccountMemo, error) {
	plain, err := accountPlaintext(item)
	if err != nil {
		return siteAccountMemo{}, err
	}
	return siteAccountMemo{publicSiteAccount(item, name), plain.Password, plain.SecurityPassword}, nil
}

func (d *DB) accountMemo(item storedSiteAccount, name string) (siteAccountMemo, error) {
	plain, err := accountPlaintext(item)
	if err != nil {
		return siteAccountMemo{}, err
	}
	return siteAccountMemo{d.decorateSiteAccount(item, name), plain.Password, plain.SecurityPassword}, nil
}

func (a *App) handleSiteAccounts(w http.ResponseWriter, r *http.Request, siteID int64, tail string) {
	w.Header().Set("Cache-Control", "no-store")
	site, err := a.db.GetSite(siteID)
	if err != nil {
		a.jsonErr(w, http.StatusNotFound, "site not found")
		return
	}
	if tail == "" {
		switch r.Method {
		case http.MethodGet:
			items, err := a.db.listSiteAccounts(siteID)
			if err != nil {
				a.jsonErr(w, 500, "账号读取失败")
				return
			}
			result := make([]siteAccountMemo, 0, len(items))
			for _, item := range items {
				memo, err := a.db.accountMemo(item, site.Name)
				if err != nil {
					a.jsonErr(w, 500, "账号信息读取失败")
					return
				}
				result = append(result, memo)
			}
			a.jsonOK(w, result)
		case http.MethodPost:
			var input SiteAccountInput
			if err := decodeJSONBody(w, r, &input); err != nil {
				a.jsonErr(w, 400, "invalid request")
				return
			}
			item, err := a.db.saveSiteAccount(siteID, 0, input)
			if err != nil {
				a.jsonErr(w, 400, err.Error())
				return
			}
			memo, err := a.db.accountMemo(*item, site.Name)
			if err != nil {
				a.jsonErr(w, 500, "账号信息读取失败")
				return
			}
			a.jsonResponse(w, http.StatusCreated, memo)
		default:
			a.jsonErr(w, 405, "method not allowed")
		}
		return
	}
	pathParts := strings.Split(strings.Trim(tail, "/"), "/")
	accountID, err := strconv.ParseInt(pathParts[0], 10, 64)
	if err != nil || accountID <= 0 {
		a.jsonErr(w, 400, "invalid account id")
		return
	}
	action := ""
	if len(pathParts) > 1 {
		action = pathParts[1]
	}
	if action == "renew" {
		if r.Method != http.MethodPost {
			a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct {
			Days int    `json:"days"`
			Note string `json:"note"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			a.jsonErr(w, http.StatusBadRequest, "invalid request")
			return
		}
		item, renewal, err := a.db.renewSiteAccount(siteID, accountID, req.Days, req.Note)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.jsonErr(w, http.StatusNotFound, "account not found")
			} else {
				a.jsonErr(w, http.StatusBadRequest, err.Error())
			}
			return
		}
		memo, err := a.db.accountMemo(*item, site.Name)
		if err != nil {
			a.jsonErr(w, http.StatusInternalServerError, "账号信息读取失败")
			return
		}
		a.jsonOK(w, map[string]any{"account": memo, "renewal": renewal})
		return
	}
	if action == "reminders" || action == "renewals" {
		if r.Method != http.MethodGet {
			a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if _, err := a.db.getSiteAccount(siteID, accountID); err != nil {
			a.jsonErr(w, http.StatusNotFound, "account not found")
			return
		}
		if action == "reminders" {
			records, err := a.db.listAccountReminderRecords(siteID, accountID)
			if err != nil {
				a.jsonErr(w, http.StatusInternalServerError, "提醒记录读取失败")
				return
			}
			a.jsonOK(w, records)
		} else {
			records, err := a.db.listAccountRenewals(siteID, accountID)
			if err != nil {
				a.jsonErr(w, http.StatusInternalServerError, "续期记录读取失败")
				return
			}
			a.jsonOK(w, records)
		}
		return
	}
	switch r.Method {
	case http.MethodPut:
		var input SiteAccountInput
		if err := decodeJSONBody(w, r, &input); err != nil {
			a.jsonErr(w, 400, "invalid request")
			return
		}
		item, err := a.db.saveSiteAccount(siteID, accountID, input)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.jsonErr(w, 404, "account not found")
			} else {
				a.jsonErr(w, 400, err.Error())
			}
			return
		}
		memo, err := a.db.accountMemo(*item, site.Name)
		if err != nil {
			a.jsonErr(w, 500, "账号信息读取失败")
			return
		}
		a.jsonOK(w, memo)
	case http.MethodDelete:
		if _, err := a.db.getSiteAccount(siteID, accountID); err != nil {
			a.jsonErr(w, 404, "account not found")
			return
		}
		if _, err := a.db.db.Exec("DELETE FROM site_accounts WHERE site_id=? AND id=?", siteID, accountID); err != nil {
			a.jsonErr(w, 500, "account delete failed")
			return
		}
		a.jsonOK(w, map[string]bool{"deleted": true})
	case http.MethodGet:
		item, err := a.db.getSiteAccount(siteID, accountID)
		if err != nil {
			a.jsonErr(w, 404, "account not found")
			return
		}
		mode := strings.TrimSpace(r.URL.Query().Get("line_mode"))
		if mode == "" {
			mode = "multi"
		}
		if mode != "original" && mode != "proxy" && mode != "multi" {
			a.jsonErr(w, http.StatusBadRequest, "line_mode must be original, proxy or multi")
			return
		}
		text, err := a.accountClientText(*site, *item, mode)
		if err != nil {
			a.jsonErr(w, 500, "账号信息读取失败")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		a.jsonOK(w, map[string]string{"text": text})
	default:
		a.jsonErr(w, 405, "method not allowed")
	}
}

func (a *App) accountClientText(site Site, item storedSiteAccount, mode string) (string, error) {
	plain, err := accountPlaintext(item)
	if err != nil {
		return "", err
	}
	return a.renderAccountClientText(site, plain, mode, siteExportOptions{IncludeAccounts: true, IncludePasswords: true}), nil
}

func (a *App) siteProxyLines(site Site) []string {
	if settings, err := a.db.telegramBotSettings(); err == nil && settings.PublicURL != "" {
		if address, err := a.telegramSiteAddress(site, settings.PublicURL); err == nil {
			return []string{address}
		}
	}
	origin := a.panelAccessURL()
	if origin == "" {
		scheme := "http"
		if a.panelTLSEnabled {
			scheme = "https"
		}
		port := a.panelListenPort
		if port <= 0 {
			if a.panelTLSEnabled {
				port = 443
			} else {
				port = 80
			}
		}
		origin = scheme + "://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	if address, err := a.telegramSiteAddress(site, origin); err == nil {
		return []string{address}
	}
	return nil
}

type siteImportRecord struct {
	Fields                     map[string]bool     `json:"-"`
	ID                         int64               `json:"-"`
	Name                       string              `json:"name"`
	TargetURL                  string              `json:"target_url"`
	ListenPort                 int                 `json:"listen_port"`
	PublicHost                 string              `json:"public_host"`
	PathPrefix                 string              `json:"path_prefix"`
	IngressMode                string              `json:"ingress_mode"`
	PrimaryLineName            string              `json:"primary_line_name"`
	PlaybackTargetURL          string              `json:"playback_target_url"`
	PlaybackMode               string              `json:"playback_mode"`
	MainVideoStreamMode        string              `json:"main_video_stream_mode"`
	FailoverTargets            []string            `json:"failover_targets"`
	FailoverLines              []FailoverLine      `json:"failover_lines"`
	StreamHosts                []string            `json:"stream_hosts"`
	UAMode                     string              `json:"ua_mode"`
	CustomUserAgent            string              `json:"custom_user_agent"`
	CustomClient               string              `json:"custom_client"`
	CustomVersion              string              `json:"custom_version"`
	ClientIPMode               string              `json:"client_ip_mode"`
	DynamicDiscoveryEnabled    bool                `json:"dynamic_discovery_enabled"`
	DynamicProfile             string              `json:"dynamic_profile"`
	DynamicDiscoverySources    []string            `json:"dynamic_discovery_sources"`
	DynamicDomainRules         []DynamicDomainRule `json:"dynamic_domain_rules"`
	DynamicAllowHTTPSDowngrade bool                `json:"dynamic_allow_https_downgrade"`
	PingCacheEnabled           bool                `json:"ping_cache_enabled"`
	ImageCacheEnabled          bool                `json:"image_cache_enabled"`
	ProgressCoalescingEnabled  bool                `json:"progress_coalescing_enabled"`
	AssetCacheEnabled          bool                `json:"asset_cache_enabled"`
	AssetCacheTTLSec           int                 `json:"asset_cache_ttl_sec"`
	AssetCacheMaxBytes         int64               `json:"asset_cache_max_bytes"`
	AssetCacheRules            string              `json:"asset_cache_rules"`
	TrafficQuota               int64               `json:"traffic_quota"`
	SpeedLimit                 int                 `json:"speed_limit"`
	TotalSpeedLimit            int                 `json:"total_speed_limit"`
	Enabled                    bool                `json:"enabled"`
	Accounts                   []SiteAccountInput  `json:"accounts"`
}
type siteDataEnvelope struct {
	Version int                `json:"version"`
	Sites   []siteImportRecord `json:"sites"`
}

func (a *App) siteDataRecords(options ...siteExportOptions) ([]siteImportRecord, error) {
	opts := siteExportOptions{IncludeAccounts: true}
	if len(options) > 0 {
		opts = options[0]
	}
	sites, err := a.db.ListSites()
	if err != nil {
		return nil, err
	}
	result := make([]siteImportRecord, 0, len(sites))
	for _, site := range sites {
		plain := []SiteAccountInput{}
		if opts.IncludeAccounts {
			accounts, err := a.db.listSiteAccounts(site.ID)
			if err != nil {
				return nil, err
			}
			for _, item := range accounts {
				v := SiteAccountInput{AccountName: item.AccountName, Username: item.Username, ExpiresAt: item.ExpiresAt, Note: item.Note, ReminderDays: item.ReminderDays}
				if opts.IncludePasswords {
					v, err = accountPlaintext(item)
					if err != nil {
						return nil, err
					}
				}
				plain = append(plain, v)
			}
		}
		result = append(result, siteImportRecord{
			ID:   site.ID,
			Name: site.Name, TargetURL: site.TargetURL, ListenPort: site.ListenPort, PublicHost: site.PublicHost,
			PathPrefix: site.PathPrefix, IngressMode: site.IngressMode, PrimaryLineName: site.PrimaryLineName,
			PlaybackTargetURL: site.PlaybackTargetURL, PlaybackMode: site.PlaybackMode, MainVideoStreamMode: site.MainVideoStreamMode,
			FailoverTargets: site.FailoverTargetList, FailoverLines: site.FailoverLines, StreamHosts: site.StreamHostList, UAMode: site.UAMode,
			CustomUserAgent: site.CustomUserAgent, CustomClient: site.CustomClient, CustomVersion: site.CustomVersion,
			ClientIPMode: site.ClientIPMode, DynamicDiscoveryEnabled: site.DynamicDiscoveryEnabled, DynamicProfile: site.DynamicProfile,
			DynamicDiscoverySources: site.DynamicDiscoverySources, DynamicDomainRules: site.DynamicDomainRules,
			DynamicAllowHTTPSDowngrade: site.DynamicAllowHTTPSDowngrade, PingCacheEnabled: site.PingCacheEnabled,
			ImageCacheEnabled: site.ImageCacheEnabled, ProgressCoalescingEnabled: site.ProgressCoalescingEnabled,
			AssetCacheEnabled: site.AssetCacheEnabled, AssetCacheTTLSec: site.AssetCacheTTLSec,
			AssetCacheMaxBytes: site.AssetCacheMaxBytes, AssetCacheRules: site.AssetCacheRules,
			TrafficQuota: site.TrafficQuota, SpeedLimit: site.SpeedLimit, TotalSpeedLimit: site.TotalSpeedLimit,
			Enabled: site.Enabled, Accounts: plain,
		})
	}
	return result, nil
}

func importSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if value == "" {
		return "site"
	}
	return value[:minInt(len(value), 24)]
}

// Prefer the registrable domain label, so subdomains and compound public
// suffixes do not leak into automatically suggested path prefixes.
func launchPathPrefix(target, fallback string) string {
	u, err := url.Parse(target)
	if err != nil {
		return importSlug(fallback)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || net.ParseIP(host) != nil {
		return importSlug(fallback)
	}
	if domain, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return importSlug(strings.SplitN(domain, ".", 2)[0])
	}
	return importSlug(strings.SplitN(host, ".", 2)[0])
}

// Field labels must begin a line (after bullets/emoji/Markdown), so generic
// “密码” never accidentally matches the tail of “安全密码”.
func launchField(text string, labels ...string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimLeftFunc(line, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
		for _, label := range labels {
			if len(line) < len(label) || !strings.EqualFold(line[:len(label)], label) {
				continue
			}
			rest := strings.TrimLeft(line[len(label):], " *_\t")
			if rest == "" || !strings.ContainsRune("|：:", []rune(rest)[0]) {
				continue
			}
			rest = strings.TrimSpace(strings.TrimLeft(rest, "|：:"))
			if strings.HasPrefix(rest, "`") {
				if end := strings.Index(rest[1:], "`"); end >= 0 {
					return rest[1 : 1+end]
				}
			}
			return strings.TrimSpace(strings.TrimSuffix(rest, "\\"))
		}
	}
	return ""
}

var launchURL = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'*+,;=%-]+`)
var launchBoldLine = regexp.MustCompile(`(?mi)^\s*\*\*([^*\r\n]+)\*\*`)

func launchTitle(text string) string {
	for _, line := range strings.Split(text, "\n") {
		match := launchBoldLine.FindStringSubmatch(line)
		if len(match) < 2 {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), strings.TrimSpace(match[0])))
		if rest == "" || rest == "\\" || strings.HasPrefix(rest, "[http") || strings.HasPrefix(rest, "http") {
			return strings.TrimSpace(match[1])
		}
	}
	return ""
}

func launchServerURLs(text string) []string {
	// Prefer explicitly named server lines over website/support links elsewhere
	// in an announcement. Messages containing only bare links still work.
	selected := []string{}
	inLines := false
	for _, line := range strings.Split(text, "\n") {
		label := strings.TrimLeftFunc(line, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
		heading := false
		for _, prefix := range []string{"当前线路", "服务器地址", "服务器线路", "Emby地址", "主地址", "主线路", "原线路", "备用线路"} {
			if strings.HasPrefix(label, prefix) {
				heading = true
				break
			}
		}
		if heading {
			inLines = true
		}
		if !inLines {
			continue
		}
		urls := launchURL.FindAllString(line, -1)
		if !heading && len(urls) > 0 && !strings.HasPrefix(label, "http://") && !strings.HasPrefix(label, "https://") {
			inLines = false
			continue
		}
		if len(urls) > 0 {
			selected = append(selected, urls...)
			continue
		}
		if !heading && strings.Trim(line, " \t\r\\") != "" {
			inLines = false
		}
	}
	if len(selected) > 0 {
		return selected
	}
	return launchURL.FindAllString(text, -1)
}

func parseSiteMessageRecord(text string) (siteImportRecord, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return siteImportRecord{}, errors.New("请粘贴开服消息")
	}
	urls := launchServerURLs(text)
	if len(urls) == 0 {
		return siteImportRecord{}, errors.New("没有找到有效的回源地址")
	}
	name := "导入站点"
	title := launchTitle(text)
	if title != "" {
		name = title
	}
	account := SiteAccountInput{
		AccountName:      launchField(text, "账号名称", "账户名称"),
		Username:         launchField(text, "用户名称", "用户名", "账号", "帐号", "账户", "username", "user"),
		Password:         launchField(text, "用户密码", "登录密码", "密码", "password", "pass"),
		SecurityPassword: launchField(text, "安全密码", "二次密码"),
		ExpiresAt:        launchField(text, "到期时间", "到期日期", "到期日", "有效期至", "expires"),
		Note:             launchField(text, "备注"),
	}
	if account.AccountName == "" {
		account.AccountName = account.Username
	}
	if account.Username == "" {
		account.Username = account.AccountName
	}
	if account.ExpiresAt == "永久" || account.ExpiresAt == "永不过期" || account.ExpiresAt == "无" {
		account.ExpiresAt = ""
	}
	// Legacy shorthand is only recognized when a three-part bold title is
	// immediately followed by a server URL. Standalone multiword titles are names.
	if account.AccountName == "" && title != "" && launchField(text, "站点名称", "服务器名称", "站点", "名称") == "" {
		for _, line := range strings.Split(text, "\n") {
			match := launchBoldLine.FindStringSubmatch(line)
			if len(match) < 2 || strings.TrimSpace(match[1]) != title {
				continue
			}
			rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), strings.TrimSpace(match[0])))
			words := strings.Fields(strings.ReplaceAll(title, "&#x20;", " "))
			if len(words) == 3 && (strings.HasPrefix(rest, "[http") || strings.HasPrefix(rest, "http")) {
				name, account.AccountName, account.Username, account.Password = words[0], words[1], words[1], words[2]
			}
			break
		}
	}
	for index, rawURL := range urls {
		urls[index] = normalizeLaunchURL(rawURL)
	}
	validURLs := urls[:0]
	seenURLs := make(map[string]struct{}, len(urls))
	for _, value := range urls {
		if value != "" {
			if _, seen := seenURLs[value]; seen {
				continue
			}
			seenURLs[value] = struct{}{}
			validURLs = append(validURLs, value)
		}
	}
	urls = validURLs
	if len(urls) == 0 {
		return siteImportRecord{}, errors.New("没有找到有效的回源地址")
	}
	if explicit := launchField(text, "站点名称", "服务器名称", "站点", "名称"); explicit != "" {
		name = explicit
	} else if heading := regexp.MustCompile(`(?m)^#{1,6}\s+([^\r\n]+)`).FindStringSubmatch(text); len(heading) > 1 {
		name = strings.TrimSpace(heading[1])
	}
	if name == "导入站点" {
		if u, err := url.Parse(urls[0]); err == nil {
			name = u.Hostname()
		}
	}
	record := siteImportRecord{PlaybackMode: "direct", MainVideoStreamMode: "proxy", DynamicDiscoveryEnabled: true, DynamicProfile: "compatible", Name: name, TargetURL: strings.TrimRight(urls[0], "，。)】"), IngressMode: ingressModePath, PathPrefix: launchPathPrefix(urls[0], name), FailoverTargets: append([]string(nil), urls[1:]...), Accounts: []SiteAccountInput{account}}
	if account.AccountName == "" && account.Username == "" {
		record.Accounts = nil
	}
	return record, nil
}

func (a *App) handleSiteMessageParse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		a.jsonErr(w, 400, "invalid request")
		return
	}
	record, err := parseSiteMessageRecord(req.Text)
	if err != nil {
		a.jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.jsonOK(w, record)
}

func normalizeLaunchURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if cut := strings.IndexAny(raw, "（("); cut >= 0 {
		raw = raw[:cut]
	}
	raw = strings.TrimRight(raw, "，。；;）)]】>")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (a *App) handleAccountReminders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	sites, err := a.db.ListSites()
	if err != nil {
		a.jsonErr(w, 500, "读取到期提醒失败")
		return
	}
	settings := a.db.currentSystemSettings()
	location := timezoneLocationByName(settings.ScheduleTimezoneName, settings.ScheduleTimezone)
	now := time.Now().In(location)
	filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	result := make([]map[string]interface{}, 0)
	for _, site := range sites {
		items, err := a.db.listSiteAccounts(site.ID)
		if err != nil {
			a.jsonErr(w, 500, "读取到期提醒失败")
			return
		}
		for _, item := range items {
			if item.ExpiresAt == "" {
				continue
			}
			parsed, err := a.db.parseSiteAccountExpiry(item.ExpiresAt)
			if err != nil {
				continue
			}
			duration := parsed.Sub(now)
			days := int(math.Ceil(duration.Hours() / 24))
			if duration < 0 {
				days = int(math.Floor(duration.Hours() / 24))
			}
			lifecycle, _ := accountLifecycleState(item.ExpiresAt, item.ReminderDays, now, location)
			status := lifecycle
			if !site.Enabled {
				status = "disabled"
			} else if item.ReminderDays == nil {
				status = "no-reminder"
			}
			if search != "" && !strings.Contains(strings.ToLower(strings.Join([]string{site.Name, item.AccountName, item.Username, item.Note}, " ")), search) {
				continue
			}
			switch filter {
			case "expired", "expiring", "active", "disabled":
				if status != filter {
					continue
				}
			case "no-reminder":
				if status != "no-reminder" {
					continue
				}
			case "upcoming":
				if parsed.Before(now) {
					continue
				}
			}
			result = append(result, map[string]interface{}{"site_id": site.ID, "site_name": site.Name, "account": a.db.decorateSiteAccount(item, site.Name), "days_left": days, "status": status, "legacy_status": map[bool]string{true: "expired", false: "upcoming"}[parsed.Before(now)], "lifecycle": lifecycle, "reminder_enabled": item.ReminderDays != nil})
		}
	}
	a.jsonOK(w, result)
}

// handleAccountReminderAction records an administrator's decision for the
// current expiry/reminder pair. Decisions are global for the account so a
// multi-admin Bot does not send the same notification after one admin handles it.
func (a *App) handleAccountReminderAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		AccountID    int64  `json:"account_id"`
		ExpiresAt    string `json:"expires_at"`
		ReminderDays int    `json:"reminder_days"`
		Action       string `json:"action"`
		SnoozeDays   int    `json:"snooze_days"`
		Note         string `json:"note"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		a.jsonErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.AccountID <= 0 || strings.TrimSpace(req.ExpiresAt) == "" || req.ReminderDays < 0 || req.ReminderDays > 3650 {
		a.jsonErr(w, http.StatusBadRequest, "提醒目标无效")
		return
	}
	account, err := a.db.getSiteAccountByID(req.AccountID)
	if err != nil || account.ExpiresAt != req.ExpiresAt || account.ReminderDays == nil || *account.ReminderDays != req.ReminderDays {
		a.jsonErr(w, http.StatusNotFound, "提醒目标不存在或已更新")
		return
	}
	if req.Action != "handled" && req.Action != "ignored" && req.Action != "snoozed" {
		a.jsonErr(w, http.StatusBadRequest, "提醒动作无效")
		return
	}
	if req.SnoozeDays <= 0 {
		req.SnoozeDays = 1
	}
	if req.SnoozeDays > 30 {
		a.jsonErr(w, http.StatusBadRequest, "延后天数应为 1–30")
		return
	}
	until := time.Time{}
	if req.Action == "snoozed" {
		until = time.Now().Add(time.Duration(req.SnoozeDays) * 24 * time.Hour)
	}
	if err := a.db.saveAccountReminderAction(req.AccountID, req.ExpiresAt, req.ReminderDays, req.Action, until, req.Note); err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "提醒动作保存失败")
		return
	}
	a.jsonOK(w, map[string]interface{}{"account_id": req.AccountID, "expires_at": req.ExpiresAt, "reminder_days": req.ReminderDays, "action": req.Action, "snoozed_until": func() string {
		if until.IsZero() {
			return ""
		}
		return until.UTC().Format(time.RFC3339)
	}()})
}

// handleAccountReminderRecords exposes the persisted delivery ledger used for
// deduplication. It intentionally contains no account credentials.
func (a *App) handleAccountReminderRecords(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var siteID, accountID int64
	if value := strings.TrimSpace(r.URL.Query().Get("site_id")); value != "" {
		siteID, _ = strconv.ParseInt(value, 10, 64)
	}
	if value := strings.TrimSpace(r.URL.Query().Get("account_id")); value != "" {
		accountID, _ = strconv.ParseInt(value, 10, 64)
	}
	records, err := a.db.listAccountReminderRecords(siteID, accountID)
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "提醒记录读取失败")
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	if status != "" || action != "" {
		filtered := records[:0]
		for _, record := range records {
			if status != "" && record.Status != status {
				continue
			}
			if action != "" && record.Action != action {
				continue
			}
			filtered = append(filtered, record)
		}
		records = filtered
	}
	a.jsonOK(w, records)
}
