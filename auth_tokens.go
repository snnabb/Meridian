package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var jwtSecret []byte
var jwtSecretEphemeral bool
var meridianSecretKey []byte
var meridianSecretKeyConfigured bool
var sessionGeneration atomic.Uint64

const (
	sessionCookieName = "meridian_session"
	sessionDuration   = 72 * time.Hour
)

func init() {
	sessionGeneration.Store(1)
	var err error
	jwtSecret, jwtSecretEphemeral, err = resolveJWTSecret(os.Getenv("JWT_SECRET"))
	if err != nil {
		panic(err)
	}
	if configured := strings.TrimSpace(os.Getenv("MERIDIAN_SECRET_KEY")); configured != "" {
		if len(configured) < 32 {
			panic("MERIDIAN_SECRET_KEY must be at least 32 bytes")
		}
		meridianSecretKey = []byte(configured)
		meridianSecretKeyConfigured = true
	}
}

func resolveJWTSecret(value string) ([]byte, bool, error) {
	if value != "" {
		if len(value) < 32 {
			return nil, false, fmt.Errorf("JWT_SECRET must be at least 32 bytes")
		}
		return []byte(value), false, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, false, fmt.Errorf("generate JWT secret: %w", err)
	}
	return secret, true, nil
}

func generateToken(userID int64, username string) (string, error) {
	header := jwtHeaderEncoded
	payload, err := json.Marshal(struct {
		Sub  int64  `json:"sub"`
		Name string `json:"name"`
		Exp  int64  `json:"exp"`
		Ver  uint64 `json:"ver"`
	}{
		Sub:  userID,
		Name: username,
		Exp:  time.Now().Add(72 * time.Hour).Unix(),
		Ver:  sessionGeneration.Load(),
	})
	if err != nil {
		return "", err
	}
	payloadEnc := base64url(payload)
	sig := hmacSHA256(header+"."+payloadEnc, jwtSecret)
	return header + "." + payloadEnc + "." + sig, nil
}

func validateToken(token string) (int64, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, "", fmt.Errorf("invalid token")
	}
	if parts[0] != jwtHeaderEncoded {
		return 0, "", fmt.Errorf("invalid token header")
	}
	expectedSig := hmacSHA256(parts[0]+"."+parts[1], jwtSecret)
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return 0, "", fmt.Errorf("invalid signature")
	}
	payload, err := base64urlDecode(parts[1])
	if err != nil {
		return 0, "", err
	}
	var claims struct {
		Sub  int64  `json:"sub"`
		Name string `json:"name"`
		Exp  int64  `json:"exp"`
		Ver  uint64 `json:"ver"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, "", err
	}
	if time.Now().Unix() > claims.Exp {
		return 0, "", fmt.Errorf("token expired")
	}
	if claims.Ver == 0 || claims.Ver != sessionGeneration.Load() {
		return 0, "", fmt.Errorf("session invalidated")
	}
	return claims.Sub, claims.Name, nil
}

func invalidateAllSessions() {
	sessionGeneration.Add(1)
}

func setSessionGeneration(value uint64) {
	if value == 0 {
		value = 1
	}
	sessionGeneration.Store(value)
}

func validateCredentialKeySeparation(credential []byte, configured bool, effectiveJWT, dynamicKey, upstreamKey []byte) error {
	if !configured || len(credential) == 0 {
		return nil
	}
	if len(effectiveJWT) > 0 && subtle.ConstantTimeCompare(credential, effectiveJWT) == 1 {
		return fmt.Errorf("MERIDIAN_SECRET_KEY must differ from JWT_SECRET")
	}
	// codeql[go/weak-cryptographic-algorithm] -- SHA-256 is used only for
	// deterministic key-separation comparisons, never for password storage.
	digest := sha256.Sum256(credential)
	if len(dynamicKey) == len(digest) && subtle.ConstantTimeCompare(digest[:], dynamicKey) == 1 {
		return fmt.Errorf("MERIDIAN_SECRET_KEY must differ from DYNAMIC_ROUTE_KEY")
	}
	if len(upstreamKey) == len(digest) && subtle.ConstantTimeCompare(digest[:], upstreamKey) == 1 {
		return fmt.Errorf("MERIDIAN_SECRET_KEY must differ from UPSTREAM_HEADER_KEY")
	}
	return nil
}

var jwtHeaderEncoded = base64url([]byte(`{"alg":"HS256","typ":"JWT"}`))

func hmacSHA256(data string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return base64url(h.Sum(nil))
}

func base64url(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64urlDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
