package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUserSessionIsValid(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	revokedBeforeNow := now.Add(-time.Minute)
	revokedAfterNow := now.Add(time.Minute)

	tests := []struct {
		name      string
		expiresAt time.Time
		revokedAt *time.Time
		want      bool
	}{
		{name: "active", expiresAt: now.Add(time.Second), want: true},
		{name: "revoked", expiresAt: now.Add(time.Hour), revokedAt: &revokedBeforeNow},
		{name: "future revocation still revoked", expiresAt: now.Add(time.Hour), revokedAt: &revokedAfterNow},
		{name: "expires exactly now", expiresAt: now},
		{name: "expired before now", expiresAt: now.Add(-time.Nanosecond)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := UserSession{ExpiresAt: tt.expiresAt, RevokedAt: tt.revokedAt}
			if got := session.IsValid(now); got != tt.want {
				t.Fatalf("IsValid() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestUserSessionJSONNeverExposesTokenHash(t *testing.T) {
	session := UserSession{
		ID:        11,
		UserID:    7,
		TokenHash: []byte("token-hash-do-not-expose"),
		ExpiresAt: time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC),
		CreatedAt: time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC),
	}

	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	logged := string(encoded)
	if strings.Contains(logged, "TokenHash") || strings.Contains(logged, "token_hash") || strings.Contains(logged, "token-hash-do-not-expose") {
		t.Fatal("UserSession JSON exposed TokenHash")
	}
}
