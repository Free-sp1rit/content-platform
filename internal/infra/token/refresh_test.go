package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

func TestParsePositiveIDRejectsNonCanonicalValues(t *testing.T) {
	for _, raw := range []string{"", "0", "-1", "+1", " 1", "1 ", "01", "9223372036854775808"} {
		t.Run(strconv.Quote(raw), func(t *testing.T) {
			if _, err := ParsePositiveID(raw); err == nil {
				t.Fatal("ParsePositiveID() succeeded")
			}
		})
	}

	for _, raw := range []string{"1", "9223372036854775807"} {
		got, err := ParsePositiveID(raw)
		if err != nil {
			t.Fatalf("ParsePositiveID(%q) error = %v", raw, err)
		}
		if strconv.FormatInt(got, 10) != raw {
			t.Fatalf("ParsePositiveID(%q) = %d", raw, got)
		}
	}
}

func TestRefreshGenerateFormatParseAndMatch(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, RefreshSecretBytes)
	codec := NewRefreshCodecWithReader(bytes.NewReader(raw))

	encoded, hash, err := codec.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	wantEncoded := base64.RawURLEncoding.EncodeToString(raw)
	if encoded != wantEncoded {
		t.Fatalf("Generate() encoded secret mismatch")
	}
	wantHash := sha256.Sum256(raw)
	if hash != wantHash {
		t.Fatal("Generate() hash mismatch")
	}

	formatted, err := codec.Format(42, encoded)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	if formatted != "42."+wantEncoded {
		t.Fatal("Format() token mismatch")
	}

	sessionID, parsedHash, err := codec.Parse(formatted)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if sessionID != 42 || parsedHash != wantHash {
		t.Fatalf("Parse() returned unexpected metadata")
	}
	if !codec.Match(parsedHash, wantHash) {
		t.Fatal("Match(valid) = false")
	}
	wrongHash := wantHash
	wrongHash[0] ^= 0xff
	if codec.Match(parsedHash, wrongHash) {
		t.Fatal("Match(wrong) = true")
	}
}

func TestRefreshConstructorsUseSecureRandomDefault(t *testing.T) {
	tests := []struct {
		name  string
		codec *RefreshCodec
	}{
		{name: "default", codec: NewRefreshCodec()},
		{name: "nil reader", codec: NewRefreshCodecWithReader(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, _, err := tt.codec.Generate()
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
			if err != nil || len(decoded) != RefreshSecretBytes {
				t.Fatalf("Generate() decoded length = %d, error = %v", len(decoded), err)
			}
			if strings.Contains(encoded, "=") {
				t.Fatal("Generate() used padding")
			}
		})
	}
}

func TestRefreshGenerateRequiresExactly32RandomBytes(t *testing.T) {
	tests := []struct {
		name   string
		reader io.Reader
	}{
		{name: "short", reader: bytes.NewReader(bytes.Repeat([]byte{1}, RefreshSecretBytes-1))},
		{name: "failure", reader: errorReader{err: errors.New("entropy unavailable")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := NewRefreshCodecWithReader(tt.reader).Generate(); err == nil {
				t.Fatal("Generate() succeeded")
			} else if strings.Contains(err.Error(), "entropy unavailable") {
				t.Fatal("Generate() exposed reader error")
			}
		})
	}
}

func TestRefreshFormatRejectsInvalidInputs(t *testing.T) {
	codec := NewRefreshCodec()
	valid := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, RefreshSecretBytes))
	tests := []struct {
		name      string
		sessionID int64
		encoded   string
	}{
		{name: "zero session", sessionID: 0, encoded: valid},
		{name: "negative session", sessionID: -1, encoded: valid},
		{name: "padding", sessionID: 1, encoded: valid + "="},
		{name: "bad alphabet", sessionID: 1, encoded: strings.Repeat("+", len(valid))},
		{name: "31 decoded bytes", sessionID: 1, encoded: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31))},
		{name: "33 decoded bytes", sessionID: 1, encoded: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := codec.Format(tt.sessionID, tt.encoded); err == nil {
				t.Fatal("Format() succeeded")
			}
		})
	}
}

func TestRefreshParseRejectsMalformedTokens(t *testing.T) {
	codec := NewRefreshCodec()
	valid := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, RefreshSecretBytes))
	tests := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "no dot", raw: "1" + valid},
		{name: "two dots", raw: "1." + valid + ".extra"},
		{name: "empty secret", raw: "1."},
		{name: "noncanonical session", raw: "01." + valid},
		{name: "overflow session", raw: "9223372036854775808." + valid},
		{name: "padding", raw: "1." + valid + "="},
		{name: "bad alphabet", raw: "1." + strings.Repeat("+", len(valid))},
		{name: "31 decoded bytes", raw: "1." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31))},
		{name: "33 decoded bytes", raw: "1." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33))},
		{name: "too long", raw: strings.Repeat("1", MaxRefreshTokenBytes+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := codec.Parse(tt.raw); err == nil {
				t.Fatal("Parse() succeeded")
			} else if strings.Contains(err.Error(), tt.raw) && tt.raw != "" {
				t.Fatal("Parse() error exposed token")
			}
		})
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
