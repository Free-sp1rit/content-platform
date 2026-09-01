package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/platform/authn"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testAccessSecret   = "0123456789abcdef0123456789abcdef"
	testAccessIssuer   = "content-platform"
	testAccessAudience = "content-platform-api"
	testJWTID          = "0123456789abcdef"
)

var testAccessNow = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func TestNewAccessManagerValidatesConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		secret   string
		issuer   string
		audience string
		wantErr  bool
	}{
		{name: "valid", secret: testAccessSecret, issuer: testAccessIssuer, audience: testAccessAudience},
		{name: "short secret", secret: strings.Repeat("s", 31), issuer: testAccessIssuer, audience: testAccessAudience, wantErr: true},
		{name: "blank issuer", secret: testAccessSecret, issuer: " ", audience: testAccessAudience, wantErr: true},
		{name: "blank audience", secret: testAccessSecret, issuer: testAccessIssuer, audience: " ", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAccessManagerWithReader(tt.secret, tt.issuer, tt.audience, bytes.NewReader(nil))
			if tt.wantErr && err == nil {
				t.Fatal("NewAccessManagerWithReader() succeeded")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("NewAccessManagerWithReader() error = %v", err)
			}
			if err != nil && tt.secret != "" && strings.Contains(err.Error(), tt.secret) {
				t.Fatal("constructor error exposed secret")
			}
		})
	}
}

func TestGenerateJWTIDUsesCSPRNGBase64URL(t *testing.T) {
	raw := bytes.Repeat([]byte{0xab}, JWTIDRandomBytes)
	manager := newTestAccessManager(t, bytes.NewReader(raw))

	got, err := manager.GenerateJWTID()
	if err != nil {
		t.Fatalf("GenerateJWTID() error = %v", err)
	}
	if got != base64.RawURLEncoding.EncodeToString(raw) {
		t.Fatal("GenerateJWTID() value mismatch")
	}
	if strings.Contains(got, "=") {
		t.Fatal("GenerateJWTID() used padding")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(got)
	if err != nil || len(decoded) < 16 {
		t.Fatalf("GenerateJWTID() decoded length = %d, error = %v", len(decoded), err)
	}

	rawToken, err := manager.Sign(1, 2, testAccessNow, testAccessNow.Add(time.Minute), got)
	if err != nil {
		t.Fatalf("Sign(generated jti) error = %v", err)
	}
	if _, err := manager.Verify(rawToken, testAccessNow); err != nil {
		t.Fatalf("Verify(generated jti) error = %v", err)
	}
}

func TestGenerateJWTIDRejectsShortOrFailingReaders(t *testing.T) {
	tests := []struct {
		name   string
		reader io.Reader
	}{
		{name: "short", reader: bytes.NewReader(bytes.Repeat([]byte{1}, JWTIDRandomBytes-1))},
		{name: "failure", reader: errorReader{err: errors.New("jti entropy do-not-log")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newTestAccessManager(t, tt.reader)
			if _, err := manager.GenerateJWTID(); err == nil {
				t.Fatal("GenerateJWTID() succeeded")
			} else if strings.Contains(err.Error(), "entropy do-not-log") {
				t.Fatal("GenerateJWTID() exposed reader error")
			}
		})
	}
}

func TestAccessSignVerifyAndPayloadWhitelist(t *testing.T) {
	manager := newTestAccessManager(t, bytes.NewReader(nil))
	issuedAt := testAccessNow.Add(-time.Minute)
	expiresAt := testAccessNow.Add(15 * time.Minute)

	raw, err := manager.Sign(42, 84, issuedAt, expiresAt, testJWTID)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if len(raw) > MaxAccessTokenBytes {
		t.Fatalf("Sign() token length = %d", len(raw))
	}

	principal, err := manager.Verify(raw, testAccessNow)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if principal != (authn.Principal{UserID: 42, SessionID: 84}) {
		t.Fatalf("Verify() principal = %+v", principal)
	}

	header := decodeJWTPart(t, raw, 0)
	if alg, ok := header["alg"].(string); !ok || alg != "HS256" {
		t.Fatalf("JWT alg = %v, want HS256", header["alg"])
	}
	payload := decodeJWTPart(t, raw, 1)
	wantKeys := map[string]struct{}{
		"iss": {}, "sub": {}, "aud": {}, "iat": {}, "exp": {}, "jti": {}, "sid": {},
	}
	if len(payload) != len(wantKeys) {
		t.Fatalf("JWT payload field count = %d, want %d", len(payload), len(wantKeys))
	}
	for key := range payload {
		if _, ok := wantKeys[key]; !ok {
			t.Fatalf("JWT payload contains unexpected field %q", key)
		}
	}
	audience, ok := payload["aud"].([]any)
	if !ok || len(audience) != 1 || audience[0] != testAccessAudience {
		t.Fatalf("JWT aud = %#v, want one-element array", payload["aud"])
	}
}

func TestAccessSignValidatesInputsAndSize(t *testing.T) {
	manager := newTestAccessManager(t, bytes.NewReader(nil))
	shortJWTID := base64.RawURLEncoding.EncodeToString(make([]byte, 11))
	longJWTID := base64.RawURLEncoding.EncodeToString(make([]byte, 97))
	paddedJWTID := base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{1}, JWTIDRandomBytes))
	noncanonicalJWTID := strings.Repeat("A", 17) + "B"
	tests := []struct {
		name      string
		userID    int64
		sessionID int64
		issuedAt  time.Time
		expiresAt time.Time
		jwtID     string
	}{
		{name: "zero user", userID: 0, sessionID: 2, issuedAt: testAccessNow, expiresAt: testAccessNow.Add(time.Minute), jwtID: testJWTID},
		{name: "negative user", userID: -1, sessionID: 2, issuedAt: testAccessNow, expiresAt: testAccessNow.Add(time.Minute), jwtID: testJWTID},
		{name: "zero session", userID: 1, sessionID: 0, issuedAt: testAccessNow, expiresAt: testAccessNow.Add(time.Minute), jwtID: testJWTID},
		{name: "negative session", userID: 1, sessionID: -1, issuedAt: testAccessNow, expiresAt: testAccessNow.Add(time.Minute), jwtID: testJWTID},
		{name: "missing issued at", userID: 1, sessionID: 2, expiresAt: testAccessNow.Add(time.Minute), jwtID: testJWTID},
		{name: "missing expires at", userID: 1, sessionID: 2, issuedAt: testAccessNow, jwtID: testJWTID},
		{name: "expiration equals issue", userID: 1, sessionID: 2, issuedAt: testAccessNow, expiresAt: testAccessNow, jwtID: testJWTID},
		{name: "expiration before issue", userID: 1, sessionID: 2, issuedAt: testAccessNow, expiresAt: testAccessNow.Add(-time.Second), jwtID: testJWTID},
		{name: "short jti", userID: 1, sessionID: 2, issuedAt: testAccessNow, expiresAt: testAccessNow.Add(time.Minute), jwtID: shortJWTID},
		{name: "long jti", userID: 1, sessionID: 2, issuedAt: testAccessNow, expiresAt: testAccessNow.Add(time.Minute), jwtID: longJWTID},
		{name: "invalid jti alphabet", userID: 1, sessionID: 2, issuedAt: testAccessNow, expiresAt: testAccessNow.Add(time.Minute), jwtID: "!!!!!!!!!!!!!!!!"},
		{name: "padded jti", userID: 1, sessionID: 2, issuedAt: testAccessNow, expiresAt: testAccessNow.Add(time.Minute), jwtID: paddedJWTID},
		{name: "noncanonical jti", userID: 1, sessionID: 2, issuedAt: testAccessNow, expiresAt: testAccessNow.Add(time.Minute), jwtID: noncanonicalJWTID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := manager.Sign(tt.userID, tt.sessionID, tt.issuedAt, tt.expiresAt, tt.jwtID); err == nil {
				t.Fatal("Sign() succeeded")
			}
		})
	}

	largeManager, err := NewAccessManager(testAccessSecret, strings.Repeat("i", MaxAccessTokenBytes), testAccessAudience)
	if err != nil {
		t.Fatalf("NewAccessManager() error = %v", err)
	}
	if _, err := largeManager.Sign(1, 2, testAccessNow, testAccessNow.Add(time.Minute), testJWTID); err == nil {
		t.Fatal("Sign() accepted oversized result")
	}

	maxJWTID := strings.Repeat("j", MaxJWTIDBytes)
	raw, err := manager.Sign(1, 2, testAccessNow, testAccessNow.Add(time.Minute), maxJWTID)
	if err != nil {
		t.Fatalf("Sign(maximum jti) error = %v", err)
	}
	if _, err := manager.Verify(raw, testAccessNow); err != nil {
		t.Fatalf("Verify(maximum jti) error = %v", err)
	}
}

func TestAccessVerifyRejectsWrongAlgorithmSignatureAndSize(t *testing.T) {
	manager := newTestAccessManager(t, bytes.NewReader(nil))
	claims := validAccessMap(testAccessNow)
	oversizedClaims := validAccessMap(testAccessNow)
	oversizedClaims["ignored"] = strings.Repeat("x", MaxAccessTokenBytes)
	oversized := signAccessMap(t, jwt.SigningMethodHS256, testAccessSecret, oversizedClaims)
	if len(oversized) <= MaxAccessTokenBytes {
		t.Fatalf("oversized JWT length = %d, want > %d", len(oversized), MaxAccessTokenBytes)
	}

	tests := []struct {
		name string
		raw  string
	}{
		{name: "HS384", raw: signAccessMap(t, jwt.SigningMethodHS384, testAccessSecret, claims)},
		{name: "none", raw: signUnsignedAccessMap(t, claims)},
		{name: "wrong signature", raw: signAccessMap(t, jwt.SigningMethodHS256, strings.Repeat("x", 32), claims)},
		{name: "malformed", raw: "access-token-do-not-log"},
		{name: "too large", raw: oversized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := manager.Verify(tt.raw, testAccessNow); !errors.Is(err, ErrInvalidAccessToken) {
				t.Fatalf("Verify() error = %v, want ErrInvalidAccessToken", err)
			} else if strings.Contains(err.Error(), "access-token-do-not-log") || strings.Contains(err.Error(), tt.raw) {
				t.Fatal("Verify() error exposed token")
			}
		})
	}
}

func signUnsignedAccessMap(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("SignedString(none) error = %v", err)
	}
	return raw
}

func TestAccessVerifyRejectsMissingClaims(t *testing.T) {
	manager := newTestAccessManager(t, bytes.NewReader(nil))
	for _, claim := range []string{"iss", "sub", "aud", "iat", "exp", "jti", "sid"} {
		t.Run(claim, func(t *testing.T) {
			claims := validAccessMap(testAccessNow)
			delete(claims, claim)
			raw := signAccessMap(t, jwt.SigningMethodHS256, testAccessSecret, claims)
			if _, err := manager.Verify(raw, testAccessNow); err == nil {
				t.Fatal("Verify() accepted missing claim")
			}
		})
	}
}

func TestAccessVerifyRejectsNonCanonicalIDs(t *testing.T) {
	manager := newTestAccessManager(t, bytes.NewReader(nil))
	invalid := []string{"", "0", "-1", "+1", " 1", "1 ", "01", "9223372036854775808"}
	for _, claim := range []string{"sub", "sid"} {
		for _, value := range invalid {
			t.Run(claim+"_"+strconv.Quote(value), func(t *testing.T) {
				claims := validAccessMap(testAccessNow)
				claims[claim] = value
				raw := signAccessMap(t, jwt.SigningMethodHS256, testAccessSecret, claims)
				if _, err := manager.Verify(raw, testAccessNow); err == nil {
					t.Fatal("Verify() accepted noncanonical identifier")
				}
			})
		}
	}
}

func TestAccessVerifyRejectsIssuerAudienceAndJWTIDViolations(t *testing.T) {
	manager := newTestAccessManager(t, bytes.NewReader(nil))
	shortJWTID := base64.RawURLEncoding.EncodeToString(make([]byte, 11))
	longJWTID := base64.RawURLEncoding.EncodeToString(make([]byte, 97))
	paddedJWTID := base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{1}, JWTIDRandomBytes))
	noncanonicalJWTID := strings.Repeat("A", 17) + "B"
	tests := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{name: "issuer mismatch", mutate: func(c jwt.MapClaims) { c["iss"] = "other-issuer" }},
		{name: "audience mismatch", mutate: func(c jwt.MapClaims) { c["aud"] = []string{"other-audience"} }},
		{name: "audience string", mutate: func(c jwt.MapClaims) { c["aud"] = testAccessAudience }},
		{name: "extra audience", mutate: func(c jwt.MapClaims) { c["aud"] = []string{testAccessAudience, "other"} }},
		{name: "short jti", mutate: func(c jwt.MapClaims) { c["jti"] = shortJWTID }},
		{name: "long jti", mutate: func(c jwt.MapClaims) { c["jti"] = longJWTID }},
		{name: "invalid jti alphabet", mutate: func(c jwt.MapClaims) { c["jti"] = "!!!!!!!!!!!!!!!!" }},
		{name: "padded jti", mutate: func(c jwt.MapClaims) { c["jti"] = paddedJWTID }},
		{name: "noncanonical jti", mutate: func(c jwt.MapClaims) { c["jti"] = noncanonicalJWTID }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := validAccessMap(testAccessNow)
			tt.mutate(claims)
			raw := signAccessMap(t, jwt.SigningMethodHS256, testAccessSecret, claims)
			if _, err := manager.Verify(raw, testAccessNow); err == nil {
				t.Fatal("Verify() accepted invalid claim")
			}
		})
	}
}

func TestAccessVerifyEnforcesExactTimeSemantics(t *testing.T) {
	manager := newTestAccessManager(t, bytes.NewReader(nil))
	tests := []struct {
		name    string
		mutate  func(jwt.MapClaims)
		wantErr bool
	}{
		{name: "valid current token", mutate: func(jwt.MapClaims) {}},
		{name: "iat exactly 30 seconds ahead", mutate: func(c jwt.MapClaims) {
			c["iat"] = testAccessNow.Add(30 * time.Second).Unix()
			c["exp"] = testAccessNow.Add(time.Minute).Unix()
		}},
		{name: "iat over 30 seconds ahead", mutate: func(c jwt.MapClaims) {
			c["iat"] = testAccessNow.Add(31 * time.Second).Unix()
			c["exp"] = testAccessNow.Add(time.Minute).Unix()
		}, wantErr: true},
		{name: "expiration equals issue", mutate: func(c jwt.MapClaims) {
			c["iat"] = testAccessNow.Add(-time.Minute).Unix()
			c["exp"] = c["iat"]
		}, wantErr: true},
		{name: "expiration before issue", mutate: func(c jwt.MapClaims) {
			c["iat"] = testAccessNow.Unix()
			c["exp"] = testAccessNow.Add(-time.Second).Unix()
		}, wantErr: true},
		{name: "expiration equals now without leeway", mutate: func(c jwt.MapClaims) {
			c["iat"] = testAccessNow.Add(-time.Minute).Unix()
			c["exp"] = testAccessNow.Unix()
		}, wantErr: true},
		{name: "expired one second", mutate: func(c jwt.MapClaims) {
			c["iat"] = testAccessNow.Add(-time.Minute).Unix()
			c["exp"] = testAccessNow.Add(-time.Second).Unix()
		}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := validAccessMap(testAccessNow)
			tt.mutate(claims)
			raw := signAccessMap(t, jwt.SigningMethodHS256, testAccessSecret, claims)
			_, err := manager.Verify(raw, testAccessNow)
			if tt.wantErr && err == nil {
				t.Fatal("Verify() succeeded")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestAccessVerifyAcceptsMaximumPositiveIDs(t *testing.T) {
	manager := newTestAccessManager(t, bytes.NewReader(nil))
	claims := validAccessMap(testAccessNow)
	claims["sub"] = strconv.FormatInt(math.MaxInt64, 10)
	claims["sid"] = strconv.FormatInt(math.MaxInt64, 10)
	raw := signAccessMap(t, jwt.SigningMethodHS256, testAccessSecret, claims)

	principal, err := manager.Verify(raw, testAccessNow)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if principal.UserID != math.MaxInt64 || principal.SessionID != math.MaxInt64 {
		t.Fatalf("Verify() principal = %+v", principal)
	}
}

func newTestAccessManager(t *testing.T, reader io.Reader) *AccessManager {
	t.Helper()
	manager, err := NewAccessManagerWithReader(testAccessSecret, testAccessIssuer, testAccessAudience, reader)
	if err != nil {
		t.Fatalf("NewAccessManagerWithReader() error = %v", err)
	}
	return manager
}

func validAccessMap(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": testAccessIssuer,
		"sub": "42",
		"aud": []string{testAccessAudience},
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"jti": testJWTID,
		"sid": "84",
	}
}

func signAccessMap(t *testing.T, method jwt.SigningMethod, secret string, claims jwt.MapClaims) string {
	t.Helper()
	raw, err := jwt.NewWithClaims(method, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return raw
}

func decodeJWTPart(t *testing.T, raw string, part int) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("JWT does not contain three parts")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[part])
	if err != nil {
		t.Fatalf("decode JWT part error = %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(decoded, &value); err != nil {
		t.Fatalf("unmarshal JWT part error = %v", err)
	}
	return value
}
