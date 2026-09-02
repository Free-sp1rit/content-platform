package domain

import "time"

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type Status string

const (
	StatusPending Status = "pending"
	StatusActive  Status = "active"
	StatusMuted   Status = "muted"
	StatusFrozen  Status = "frozen"
	StatusBanned  Status = "banned"
	StatusDeleted Status = "deleted"
)

type User struct {
	ID             int64      `json:"id"`
	Email          string     `json:"email"`
	PasswordHash   string     `json:"-"`
	DisplayName    string     `json:"display_name"`
	Bio            string     `json:"bio"`
	Role           Role       `json:"role"`
	Status         Status     `json:"status"`
	MutedUntil     *time.Time `json:"muted_until"`
	ViolationCount int        `json:"violation_count"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeletedAt      *time.Time `json:"deleted_at"`
}

type UserView struct {
	ID             int64      `json:"id"`
	Email          string     `json:"email"`
	DisplayName    string     `json:"display_name"`
	Bio            string     `json:"bio"`
	Role           Role       `json:"role"`
	Status         Status     `json:"status"`
	MutedUntil     *time.Time `json:"muted_until"`
	ViolationCount int        `json:"violation_count"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeletedAt      *time.Time `json:"deleted_at"`
}

type PublicUserView struct {
	ID          int64     `json:"id"`
	DisplayName string    `json:"display_name"`
	Bio         string    `json:"bio"`
	Role        Role      `json:"role"`
	Status      Status    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s Status) CanLogin() bool {
	switch s {
	case StatusPending, StatusActive, StatusMuted, StatusFrozen:
		return true
	default:
		return false
	}
}

func (s Status) CanReadSelf() bool {
	switch s {
	case StatusPending, StatusActive, StatusMuted, StatusFrozen:
		return true
	default:
		return false
	}
}

func (s Status) CanEditProfile() bool {
	switch s {
	case StatusPending, StatusActive, StatusMuted:
		return true
	default:
		return false
	}
}

func (s Status) CanDeleteAccount() bool {
	switch s {
	case StatusPending, StatusActive, StatusMuted:
		return true
	default:
		return false
	}
}

func (s Status) CanWriteArticle() bool {
	return s.allowsContentWrites()
}

func (s Status) CanWriteComment() bool {
	return s.allowsContentWrites()
}

func (s Status) CanInteract() bool {
	return s.allowsContentWrites()
}

func (s Status) CanRepost() bool {
	return s.allowsContentWrites()
}

func (s Status) CanSendMessage() bool {
	return s.allowsContentWrites()
}

func (s Status) allowsContentWrites() bool {
	return s == StatusActive
}

func (u User) View() UserView {
	return UserView{
		ID:             u.ID,
		Email:          u.Email,
		DisplayName:    u.DisplayName,
		Bio:            u.Bio,
		Role:           u.Role,
		Status:         u.Status,
		MutedUntil:     normalizeOptionalTime(u.MutedUntil),
		ViolationCount: u.ViolationCount,
		CreatedAt:      NormalizeTime(u.CreatedAt),
		UpdatedAt:      NormalizeTime(u.UpdatedAt),
		DeletedAt:      normalizeOptionalTime(u.DeletedAt),
	}
}

func (u User) PublicView() PublicUserView {
	view := PublicUserView{
		ID:          u.ID,
		DisplayName: u.DisplayName,
		Bio:         u.Bio,
		Role:        u.Role,
		Status:      u.Status,
		CreatedAt:   NormalizeTime(u.CreatedAt),
	}
	if u.Status == StatusDeleted {
		view.DisplayName = "Deleted User"
		view.Bio = ""
		view.Role = RoleUser
		view.Status = StatusDeleted
	}
	return view
}

func normalizeOptionalTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := NormalizeTime(*value)
	return &normalized
}
