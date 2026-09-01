package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/platform/authn"
	"github.com/golang-jwt/jwt/v5"
)

const (
	MaxAccessTokenBytes = 4096
	MinJWTIDBytes       = 16
	MaxJWTIDBytes       = 128
	JWTIDRandomBytes    = 16
	maxFutureIssuedAt   = 30 * time.Second
)

var (
	ErrInvalidAccessConfig = errors.New("access token configuration is invalid")
	ErrInvalidAccessClaims = errors.New("access token claims are invalid")
	ErrInvalidAccessToken  = errors.New("access token is invalid")
)

type AccessManager struct {
	secret   []byte
	issuer   string
	audience string
	random   io.Reader
}

func NewAccessManager(secret, issuer, audience string) (*AccessManager, error) {
	return NewAccessManagerWithReader(secret, issuer, audience, rand.Reader)
}

func NewAccessManagerWithReader(secret, issuer, audience string, random io.Reader) (*AccessManager, error) {
	if len(secret) < 32 || strings.TrimSpace(issuer) == "" || strings.TrimSpace(audience) == "" {
		return nil, ErrInvalidAccessConfig
	}
	if random == nil {
		random = rand.Reader
	}
	return &AccessManager{
		secret:   append([]byte(nil), secret...),
		issuer:   issuer,
		audience: audience,
		random:   random,
	}, nil
}

func (m *AccessManager) GenerateJWTID() (string, error) {
	raw := make([]byte, JWTIDRandomBytes)
	if _, err := io.ReadFull(m.random, raw); err != nil {
		return "", ErrRandomSource
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (m *AccessManager) Sign(userID, sessionID int64, issuedAt, expiresAt time.Time, jwtID string) (string, error) {
	if userID <= 0 || sessionID <= 0 || issuedAt.IsZero() || expiresAt.IsZero() || !validJWTID(jwtID) {
		return "", ErrInvalidAccessClaims
	}
	issuedAtUnix := issuedAt.Unix()
	expiresAtUnix := expiresAt.Unix()
	if expiresAtUnix <= issuedAtUnix {
		return "", ErrInvalidAccessClaims
	}

	claims := accessTokenClaims{
		Issuer:        m.issuer,
		Subject:       strconv.FormatInt(userID, 10),
		Audience:      []string{m.audience},
		IssuedAtUnix:  &issuedAtUnix,
		ExpiresAtUnix: &expiresAtUnix,
		JWTID:         jwtID,
		SessionID:     strconv.FormatInt(sessionID, 10),
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", ErrInvalidAccessToken
	}
	if len(raw) > MaxAccessTokenBytes {
		return "", ErrInvalidAccessToken
	}
	return raw, nil
}

func (m *AccessManager) Verify(raw string, now time.Time) (authn.Principal, error) {
	if raw == "" || len(raw) > MaxAccessTokenBytes || now.IsZero() {
		return authn.Principal{}, ErrInvalidAccessToken
	}

	claims := accessTokenClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithoutClaimsValidation(),
	)
	parsed, err := parser.ParseWithClaims(raw, &claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalidAccessToken
		}
		return m.secret, nil
	})
	if err != nil || parsed == nil || !parsed.Valid {
		return authn.Principal{}, ErrInvalidAccessToken
	}

	userID, err := ParsePositiveID(claims.Subject)
	if err != nil {
		return authn.Principal{}, ErrInvalidAccessToken
	}
	sessionID, err := ParsePositiveID(claims.SessionID)
	if err != nil {
		return authn.Principal{}, ErrInvalidAccessToken
	}
	if claims.Issuer != m.issuer || len(claims.Audience) != 1 || claims.Audience[0] != m.audience {
		return authn.Principal{}, ErrInvalidAccessToken
	}
	if claims.IssuedAtUnix == nil || claims.ExpiresAtUnix == nil || !validJWTID(claims.JWTID) {
		return authn.Principal{}, ErrInvalidAccessToken
	}

	issuedAt := time.Unix(*claims.IssuedAtUnix, 0).UTC()
	expiresAt := time.Unix(*claims.ExpiresAtUnix, 0).UTC()
	if !expiresAt.After(issuedAt) || !expiresAt.After(now) || issuedAt.After(now.Add(maxFutureIssuedAt)) {
		return authn.Principal{}, ErrInvalidAccessToken
	}

	return authn.Principal{UserID: userID, SessionID: sessionID}, nil
}

func validJWTID(value string) bool {
	if len(value) < MinJWTIDBytes || len(value) > MaxJWTIDBytes || strings.Contains(value, "=") {
		return false
	}

	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return false
	}

	return base64.RawURLEncoding.EncodeToString(decoded) == value
}

type accessTokenClaims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      []string `json:"aud"`
	IssuedAtUnix  *int64   `json:"iat"`
	ExpiresAtUnix *int64   `json:"exp"`
	JWTID         string   `json:"jti"`
	SessionID     string   `json:"sid"`
}

func (c accessTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return numericDate(c.ExpiresAtUnix), nil
}

func (c accessTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return numericDate(c.IssuedAtUnix), nil
}

func (c accessTokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

func (c accessTokenClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c accessTokenClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

func (c accessTokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings(c.Audience), nil
}

func numericDate(value *int64) *jwt.NumericDate {
	if value == nil {
		return nil
	}
	return jwt.NewNumericDate(time.Unix(*value, 0).UTC())
}
