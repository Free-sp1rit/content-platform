package domain

import "time"

type UserSession struct {
	ID        int64      `json:"id"`
	UserID    int64      `json:"user_id"`
	TokenHash []byte     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	CreatedAt time.Time  `json:"created_at"`
}

func (s UserSession) IsValid(now time.Time) bool {
	return s.RevokedAt == nil && s.ExpiresAt.After(now)
}
