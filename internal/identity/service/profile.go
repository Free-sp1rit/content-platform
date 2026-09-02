package service

import (
	"context"
	"errors"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
)

type MeInput struct {
	UserID    int64
	SessionID int64
	RequestID string
}

type PublicUserInput struct {
	UserID    int64
	RequestID string
}

func (s *Service) Me(ctx context.Context, input MeInput) (domain.UserView, error) {
	result, err := s.authenticate(ctx, AuthenticateInput{
		UserID:    input.UserID,
		SessionID: input.SessionID,
	}, input.RequestID)
	if err != nil {
		return domain.UserView{}, err
	}
	return result.User.View(), nil
}

func (s *Service) PublicUser(ctx context.Context, input PublicUserInput) (domain.PublicUserView, error) {
	if input.UserID <= 0 {
		return domain.PublicUserView{}, newInternalError(nil)
	}
	if err := profileContextError(ctx); err != nil {
		return domain.PublicUserView{}, err
	}

	user, err := s.repository.FindUser(ctx, input.UserID)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return domain.PublicUserView{}, newInternalError(ctxErr)
	}
	if err != nil {
		return domain.PublicUserView{}, publicUserLookupError(err)
	}
	if !validProfileUserStructure(user, input.UserID, true) {
		return domain.PublicUserView{}, newInternalError(nil)
	}

	now, err := s.now()
	if err != nil {
		return domain.PublicUserView{}, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return domain.PublicUserView{}, newInternalError(ctxErr)
	}
	if shouldRecoverExpiredMute(user, now) {
		user, err = s.recoverExpiredMuteAfterRead(ctx, user, now, input.RequestID)
		if err != nil {
			if err == ErrNotFound {
				return domain.PublicUserView{}, ErrUserNotFound
			}
			return domain.PublicUserView{}, newInternalError(err)
		}
		if !validProfileUserStructure(user, input.UserID, true) {
			return domain.PublicUserView{}, newInternalError(nil)
		}
	}

	return user.PublicView(), nil
}

func (s *Service) recoverExpiredMuteAfterRead(
	ctx context.Context,
	observed domain.User,
	now time.Time,
	requestID string,
) (domain.User, error) {
	if !shouldRecoverExpiredMute(observed, now) {
		return secretFreeUser(observed), nil
	}

	var latest domain.User
	err := s.repository.WithinTx(ctx, func(txCtx context.Context, tx Tx) error {
		lockedUsers, err := tx.LockUsers(txCtx, []int64{observed.ID})
		if err != nil {
			return newInternalError(err)
		}
		if len(lockedUsers) == 0 {
			return ErrNotFound
		}
		if len(lockedUsers) != 1 || lockedUsers[0].ID != observed.ID {
			return newInternalError(nil)
		}

		current := lockedUsers[0]
		if !validProfileUserStructure(current, observed.ID, false) {
			return newInternalError(nil)
		}
		current, pendingAudit, err := recoverExpiredMuteForAuth(txCtx, tx, current, now, requestID)
		if err != nil {
			return err
		}
		if !validProfileUserStructure(current, observed.ID, false) {
			return newInternalError(nil)
		}
		if pendingAudit != nil {
			if err := tx.InsertAudit(txCtx, *pendingAudit); err != nil {
				return newInternalError(err)
			}
		}
		latest = secretFreeUser(current)
		return nil
	})
	if err != nil {
		if err == ErrNotFound {
			return domain.User{}, ErrNotFound
		}
		return domain.User{}, newInternalError(err)
	}
	if !validProfileUserStructure(latest, observed.ID, true) {
		return domain.User{}, newInternalError(nil)
	}
	return latest, nil
}

func strictAuthenticationUserError(user domain.User, expectedID int64, secretFree bool) error {
	if !validProfileUserFields(user, expectedID, secretFree) {
		return newInternalError(nil)
	}
	if user.DeletedAt != nil {
		return ErrSessionInvalid
	}
	switch user.Status {
	case domain.StatusBanned, domain.StatusDeleted:
		return ErrSessionInvalid
	case domain.StatusMuted:
		if user.MutedUntil == nil {
			return newInternalError(nil)
		}
	case domain.StatusPending, domain.StatusActive, domain.StatusFrozen:
		if user.MutedUntil != nil {
			return newInternalError(nil)
		}
	default:
		return newInternalError(nil)
	}
	return nil
}

func validProfileUserStructure(user domain.User, expectedID int64, secretFree bool) bool {
	if !validProfileUserFields(user, expectedID, secretFree) {
		return false
	}
	switch user.Status {
	case domain.StatusMuted:
		return user.MutedUntil != nil && user.DeletedAt == nil
	case domain.StatusDeleted:
		return user.MutedUntil == nil && user.DeletedAt != nil
	case domain.StatusPending, domain.StatusActive, domain.StatusFrozen, domain.StatusBanned:
		return user.MutedUntil == nil && user.DeletedAt == nil
	default:
		return false
	}
}

func validProfileUserFields(user domain.User, expectedID int64, secretFree bool) bool {
	if user.ID <= 0 || user.ID != expectedID || !validUserRole(user.Role) {
		return false
	}
	if secretFree && user.PasswordHash != "" {
		return false
	}
	if user.Email != domain.NormalizeEmail(user.Email) || domain.ValidateEmail(user.Email) != nil {
		return false
	}
	if user.DisplayName != domain.NormalizeDisplayName(user.DisplayName) || domain.ValidateDisplayName(user.DisplayName) != nil {
		return false
	}
	if domain.ValidateBio(user.Bio) != nil || user.ViolationCount < 0 {
		return false
	}
	if !validAuthenticationTime(user.CreatedAt) || !validAuthenticationTime(user.UpdatedAt) || user.UpdatedAt.Before(user.CreatedAt) {
		return false
	}
	if user.MutedUntil != nil && !validAuthenticationTime(*user.MutedUntil) {
		return false
	}
	if user.DeletedAt != nil && (!validAuthenticationTime(*user.DeletedAt) || user.DeletedAt.Before(user.CreatedAt)) {
		return false
	}
	return true
}

func shouldRecoverExpiredMute(user domain.User, now time.Time) bool {
	return user.Status == domain.StatusMuted &&
		user.MutedUntil != nil &&
		!user.MutedUntil.After(now)
}

func secretFreeUser(user domain.User) domain.User {
	user.PasswordHash = ""
	return user
}

func publicUserLookupError(err error) error {
	if internalContextMarker(err) != nil || errors.Is(err, ErrInternal) {
		return newInternalError(err)
	}
	if errors.Is(err, ErrNotFound) {
		return ErrUserNotFound
	}
	return newInternalError(err)
}

func profileContextError(ctx context.Context) error {
	if ctx == nil {
		return newInternalError(nil)
	}
	if err := ctx.Err(); err != nil {
		return newInternalError(err)
	}
	return nil
}
