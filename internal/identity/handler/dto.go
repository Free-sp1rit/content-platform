package handler

import (
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
)

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type updateMeRequest struct {
	DisplayName *string `json:"display_name"`
	Bio         *string `json:"bio"`
}

type changeStatusRequest struct {
	Status     domain.Status `json:"status"`
	Reason     *string       `json:"reason"`
	MutedUntil *string       `json:"muted_until"`
}

type userResponse struct {
	ID             int64         `json:"id"`
	Email          string        `json:"email"`
	DisplayName    string        `json:"display_name"`
	Bio            string        `json:"bio"`
	Role           domain.Role   `json:"role"`
	Status         domain.Status `json:"status"`
	MutedUntil     *time.Time    `json:"muted_until"`
	ViolationCount int           `json:"violation_count"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
	DeletedAt      *time.Time    `json:"deleted_at"`
}

type publicUserResponse struct {
	ID          int64         `json:"id"`
	DisplayName string        `json:"display_name"`
	Bio         string        `json:"bio"`
	Role        domain.Role   `json:"role"`
	Status      domain.Status `json:"status"`
	CreatedAt   time.Time     `json:"created_at"`
}

type loginResponse struct {
	TokenType        string       `json:"token_type"`
	AccessToken      string       `json:"access_token"`
	ExpiresIn        int64        `json:"expires_in"`
	RefreshToken     string       `json:"refresh_token"`
	RefreshExpiresAt time.Time    `json:"refresh_expires_at"`
	User             userResponse `json:"user"`
}

type refreshResponse struct {
	TokenType        string    `json:"token_type"`
	AccessToken      string    `json:"access_token"`
	ExpiresIn        int64     `json:"expires_in"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

type logoutResponse struct {
	LoggedOut bool `json:"logged_out"`
}

type deleteResponse struct {
	Deleted bool `json:"deleted"`
}

func newUserResponse(user domain.UserView) userResponse {
	return userResponse{
		ID: user.ID, Email: user.Email, DisplayName: user.DisplayName, Bio: user.Bio,
		Role: user.Role, Status: user.Status, MutedUntil: normalizeOptionalTime(user.MutedUntil),
		ViolationCount: user.ViolationCount, CreatedAt: normalizeTime(user.CreatedAt),
		UpdatedAt: normalizeTime(user.UpdatedAt), DeletedAt: normalizeOptionalTime(user.DeletedAt),
	}
}

func newPublicUserResponse(user domain.PublicUserView) publicUserResponse {
	return publicUserResponse{
		ID: user.ID, DisplayName: user.DisplayName, Bio: user.Bio, Role: user.Role,
		Status: user.Status, CreatedAt: normalizeTime(user.CreatedAt),
	}
}

func newLoginResponse(result identityservice.LoginResult) loginResponse {
	return loginResponse{
		TokenType: result.TokenType, AccessToken: result.AccessToken, ExpiresIn: result.ExpiresIn,
		RefreshToken: result.RefreshToken, RefreshExpiresAt: normalizeTime(result.RefreshExpiresAt),
		User: newUserResponse(result.User),
	}
}

func newRefreshResponse(result identityservice.RefreshResult) refreshResponse {
	return refreshResponse{
		TokenType: result.TokenType, AccessToken: result.AccessToken, ExpiresIn: result.ExpiresIn,
		RefreshToken: result.RefreshToken, RefreshExpiresAt: normalizeTime(result.RefreshExpiresAt),
	}
}

func normalizeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Second)
}

func normalizeOptionalTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := normalizeTime(*value)
	return &normalized
}
