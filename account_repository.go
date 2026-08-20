package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func configuredSetupToken(userCount int, value string) (string, error) {
	if userCount > 0 {
		return "", nil
	}
	token := strings.TrimSpace(value)
	if token == "" {
		return "", errors.New("SETUP_TOKEN must be configured before creating the first administrator")
	}
	if len(token) < 32 {
		return "", errors.New("SETUP_TOKEN must be at least 32 bytes")
	}
	return token, nil
}

func setupTokenMatches(expected, provided string) bool {
	expectedHash := sha256.Sum256([]byte(expected))
	providedHash := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1
}

func (d *DB) UserCount() (int, error) {
	var n int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

var errAdminAlreadyExists = errors.New("admin user already exists")
var errInvalidCredentials = errors.New("invalid username or password")
var errAdminNotConfigured = errors.New("administrator is not configured")
var errMultipleAdmins = errors.New("multiple administrator accounts found")
var errInvalidAdminPassword = errors.New("password must be 12-72 bytes")
var errInvalidAdminUsername = errors.New("username must be 1-64 characters")
var errNoAccountChanges = errors.New("no account changes requested")

func validateAdminPassword(password string) error {
	if len(password) < 12 || len(password) > 72 {
		return errInvalidAdminPassword
	}
	return nil
}

func validateAdminUsername(username string) error {
	if username == "" || len(username) > 64 {
		return errInvalidAdminUsername
	}
	return nil
}

type AdminAccount struct {
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

func (d *DB) AdminAccountByID(userID int64) (AdminAccount, error) {
	var account AdminAccount
	err := d.db.QueryRow(`
		SELECT username, COALESCE(CAST(created_at AS TEXT), '')
		FROM users
		WHERE id=?`, userID).Scan(&account.Username, &account.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminAccount{}, errAdminNotConfigured
	}
	if err != nil {
		return AdminAccount{}, err
	}
	account.Role = "管理员"
	return account, nil
}

func (d *DB) UpdateAdminAccount(userID int64, currentPassword, username, newPassword string) (AdminAccount, error) {
	username = strings.TrimSpace(username)
	if err := validateAdminUsername(username); err != nil {
		return AdminAccount{}, err
	}
	if currentPassword == "" || len(currentPassword) > 72 {
		return AdminAccount{}, errInvalidCredentials
	}
	if newPassword != "" {
		if err := validateAdminPassword(newPassword); err != nil {
			return AdminAccount{}, err
		}
	}

	var currentUsername, currentHash, createdAt string
	err := d.db.QueryRow(`
		SELECT username, password_hash, COALESCE(CAST(created_at AS TEXT), '')
		FROM users
		WHERE id=?`, userID).Scan(&currentUsername, &currentHash, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminAccount{}, errAdminNotConfigured
	}
	if err != nil {
		return AdminAccount{}, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(currentPassword)); err != nil {
		return AdminAccount{}, errInvalidCredentials
	}
	if username == currentUsername && newPassword == "" {
		return AdminAccount{}, errNoAccountChanges
	}

	nextHash := currentHash
	if newPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return AdminAccount{}, err
		}
		nextHash = string(hash)
	}
	tx, err := d.db.Begin()
	if err != nil {
		return AdminAccount{}, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`
			UPDATE users
		SET username=?, password_hash=?
		WHERE id=? AND username=? AND password_hash=?`, username, nextHash, userID, currentUsername, currentHash)
	if err != nil {
		if isSQLiteUniqueConstraintError(err) {
			return AdminAccount{}, errInvalidAdminUsername
		}
		return AdminAccount{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return AdminAccount{}, err
	}
	if rows != 1 {
		return AdminAccount{}, errors.New("administrator account changed concurrently")
	}
	epoch, err := d.BumpSessionEpochTx(tx)
	if err != nil {
		return AdminAccount{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdminAccount{}, err
	}
	setSessionGeneration(epoch)
	return AdminAccount{Username: username, Role: "管理员", CreatedAt: createdAt}, nil
}

func (d *DB) CreateInitialUser(username, password string) (int64, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	res, err := d.db.Exec(`
		INSERT INTO users (username, password_hash)
		SELECT ?, ?
		WHERE NOT EXISTS (SELECT 1 FROM users)
	`, username, string(hash))
	if err != nil {
		return 0, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if rows != 1 {
		return 0, errAdminAlreadyExists
	}
	return res.LastInsertId()
}

var invalidUserPasswordHash = func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("meridian-invalid-user"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return hash
}()

func (d *DB) VerifyUser(username, password string) (int64, error) {
	var id int64
	var hash string
	err := d.db.QueryRow("SELECT id, password_hash FROM users WHERE username=?", username).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(invalidUserPasswordHash, []byte(password))
		return 0, errInvalidCredentials
	}
	if err != nil {
		return 0, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return 0, errInvalidCredentials
	}
	return id, nil
}

func (d *DB) ResetAdminPassword(password string) error {
	if err := validateAdminPassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	switch {
	case count == 0:
		return errAdminNotConfigured
	case count != 1:
		return errMultipleAdmins
	}

	result, err := tx.Exec("UPDATE users SET password_hash=?", string(hash))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("updated %d administrator rows, want 1", rows)
	}
	epoch, err := d.BumpSessionEpochTx(tx)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	setSessionGeneration(epoch)
	return nil
}
