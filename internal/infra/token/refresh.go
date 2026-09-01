package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
)

const (
	RefreshSecretBytes   = 32
	MaxRefreshTokenBytes = 256
)

var (
	ErrInvalidPositiveID = errors.New("identifier must be a canonical positive integer")
	ErrInvalidRefresh    = errors.New("refresh token is invalid")
	ErrRandomSource      = errors.New("generate secure random value")
)

type RefreshCodec struct {
	random io.Reader
}

func NewRefreshCodec() *RefreshCodec {
	return NewRefreshCodecWithReader(rand.Reader)
}

func NewRefreshCodecWithReader(random io.Reader) *RefreshCodec {
	if random == nil {
		random = rand.Reader
	}
	return &RefreshCodec{random: random}
}

func (c *RefreshCodec) Generate() (string, [sha256.Size]byte, error) {
	raw := make([]byte, RefreshSecretBytes)
	if _, err := io.ReadFull(c.random, raw); err != nil {
		return "", [sha256.Size]byte{}, ErrRandomSource
	}
	return base64.RawURLEncoding.EncodeToString(raw), sha256.Sum256(raw), nil
}

func (c *RefreshCodec) Format(sessionID int64, encodedSecret string) (string, error) {
	if sessionID <= 0 {
		return "", ErrInvalidRefresh
	}
	if _, err := decodeRefreshSecret(encodedSecret); err != nil {
		return "", ErrInvalidRefresh
	}
	token := strconv.FormatInt(sessionID, 10) + "." + encodedSecret
	if len(token) > MaxRefreshTokenBytes {
		return "", ErrInvalidRefresh
	}
	return token, nil
}

func (c *RefreshCodec) Parse(raw string) (int64, [sha256.Size]byte, error) {
	if len(raw) == 0 || len(raw) > MaxRefreshTokenBytes || strings.Count(raw, ".") != 1 {
		return 0, [sha256.Size]byte{}, ErrInvalidRefresh
	}
	sessionRaw, encodedSecret, _ := strings.Cut(raw, ".")
	sessionID, err := ParsePositiveID(sessionRaw)
	if err != nil {
		return 0, [sha256.Size]byte{}, ErrInvalidRefresh
	}
	secret, err := decodeRefreshSecret(encodedSecret)
	if err != nil {
		return 0, [sha256.Size]byte{}, ErrInvalidRefresh
	}
	return sessionID, sha256.Sum256(secret), nil
}

func (c *RefreshCodec) Match(wantHash, candidateHash [sha256.Size]byte) bool {
	return subtle.ConstantTimeCompare(wantHash[:], candidateHash[:]) == 1
}

func ParsePositiveID(raw string) (int64, error) {
	if raw == "" || raw[0] < '1' || raw[0] > '9' {
		return 0, ErrInvalidPositiveID
	}
	for i := 1; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, ErrInvalidPositiveID
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 || strconv.FormatInt(value, 10) != raw {
		return 0, ErrInvalidPositiveID
	}
	return value, nil
}

func decodeRefreshSecret(encoded string) ([]byte, error) {
	if encoded == "" || strings.Contains(encoded, "=") {
		return nil, ErrInvalidRefresh
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != RefreshSecretBytes {
		return nil, ErrInvalidRefresh
	}
	if base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return nil, ErrInvalidRefresh
	}
	return raw, nil
}
