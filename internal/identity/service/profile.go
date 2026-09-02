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

type UpdateMeInput struct {
	UserID      int64
	SessionID   int64
	RequestID   string
	DisplayName Field[string]
	Bio         Field[string]
}

type DeleteMeInput struct {
	UserID    int64
	SessionID int64
	RequestID string
}

type DeleteMeResult struct {
	Deleted bool
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

func (s *Service) UpdateMe(ctx context.Context, input UpdateMeInput) (domain.UserView, error) {
	if input.DisplayName.Set {
		input.DisplayName.Value = domain.NormalizeDisplayName(input.DisplayName.Value)
		if err := domain.ValidateDisplayName(input.DisplayName.Value); err != nil {
			return domain.UserView{}, newValidationError(ValidationFieldDisplayName)
		}
	}
	if input.Bio.Set {
		if err := domain.ValidateBio(input.Bio.Value); err != nil {
			return domain.UserView{}, newValidationError(ValidationFieldBio)
		}
	}
	if input.UserID <= 0 || input.SessionID <= 0 {
		return domain.UserView{}, ErrSessionInvalid
	}
	if err := profileContextError(ctx); err != nil {
		return domain.UserView{}, err
	}

	var updated domain.User
	err := s.repository.WithinTx(ctx, func(txCtx context.Context, tx Tx) error {
		users, err := tx.LockUsers(txCtx, []int64{input.UserID})
		if err != nil {
			return newInternalError(err)
		}
		if len(users) == 0 {
			return ErrSessionInvalid
		}
		if len(users) != 1 || users[0].ID != input.UserID {
			return newInternalError(nil)
		}
		user := users[0]

		session, err := tx.LockSession(txCtx, input.SessionID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return ErrSessionInvalid
			}
			return newInternalError(err)
		}
		if !validAuthenticationSessionStructure(AuthenticationSession{
			ID: session.ID, UserID: session.UserID, ExpiresAt: session.ExpiresAt,
			RevokedAt: session.RevokedAt, CreatedAt: session.CreatedAt,
		}, input.SessionID) {
			return newInternalError(nil)
		}
		if session.UserID != input.UserID || session.RevokedAt != nil {
			return ErrSessionInvalid
		}
		if err := strictAuthenticationUserError(user, input.UserID, false); err != nil {
			return err
		}
		now, err := s.now()
		if err != nil {
			return err
		}
		if !domain.NormalizeTime(session.ExpiresAt).After(now) {
			return ErrSessionInvalid
		}

		user, pendingAudit, err := recoverExpiredMuteForAuth(txCtx, tx, user, now, input.RequestID)
		if err != nil {
			return err
		}
		if user.Status == domain.StatusFrozen {
			return ErrUserFrozen
		}
		if !user.Status.CanEditProfile() {
			return ErrSessionInvalid
		}

		mutation := UserMutation{UserID: user.ID}
		if input.DisplayName.Set && input.DisplayName.Value != user.DisplayName {
			mutation.DisplayName = input.DisplayName
		}
		if input.Bio.Set && input.Bio.Value != user.Bio {
			mutation.Bio = input.Bio
		}
		if mutation.DisplayName.Set || mutation.Bio.Set {
			mutation.UpdatedAt = SetField(now)
			previous := user
			user, err = tx.UpdateUser(txCtx, mutation)
			if err != nil {
				return newInternalError(err)
			}
			if !validProfileMutationResult(user, previous, mutation, now) {
				return newInternalError(nil)
			}
		}
		if pendingAudit != nil {
			if err := tx.InsertAudit(txCtx, *pendingAudit); err != nil {
				return newInternalError(err)
			}
		}
		updated = secretFreeUser(user)
		return nil
	})
	if err != nil {
		switch err {
		case ErrSessionInvalid, ErrUserFrozen:
			return domain.UserView{}, err
		}
		return domain.UserView{}, newInternalError(err)
	}
	if !validProfileUserStructure(updated, input.UserID, true) {
		return domain.UserView{}, newInternalError(nil)
	}
	return updated.View(), nil
}

func (s *Service) DeleteMe(ctx context.Context, input DeleteMeInput) (DeleteMeResult, error) {
	if input.UserID <= 0 || input.SessionID <= 0 {
		return DeleteMeResult{}, ErrSessionInvalid
	}
	if err := profileContextError(ctx); err != nil {
		return DeleteMeResult{}, err
	}

	result := DeleteMeResult{}
	err := s.repository.WithinTx(ctx, func(txCtx context.Context, tx Tx) error {
		users, err := tx.LockUsers(txCtx, []int64{input.UserID})
		if err != nil {
			return newInternalError(err)
		}
		if len(users) == 0 {
			return ErrSessionInvalid
		}
		if len(users) != 1 || users[0].ID != input.UserID {
			return newInternalError(nil)
		}
		user := users[0]

		sessions, err := tx.LockActiveSessions(txCtx, input.UserID)
		if err != nil {
			return newInternalError(err)
		}
		currentFound, sessionIDs, err := validateLockedActiveSessions(sessions, input.UserID, input.SessionID)
		if err != nil {
			return err
		}
		if !currentFound {
			return ErrSessionInvalid
		}
		if err := strictAuthenticationUserError(user, input.UserID, false); err != nil {
			return err
		}
		now, err := s.now()
		if err != nil {
			return err
		}
		for _, session := range sessions {
			if session.ID == input.SessionID && !domain.NormalizeTime(session.ExpiresAt).After(now) {
				return ErrSessionInvalid
			}
		}

		user, pendingAudit, err := recoverExpiredMuteForAuth(txCtx, tx, user, now, input.RequestID)
		if err != nil {
			return err
		}
		if user.Status == domain.StatusFrozen {
			return ErrUserFrozen
		}
		if !user.Status.CanDeleteAccount() {
			return ErrSessionInvalid
		}

		deletedAt := now
		mutation := UserMutation{
			UserID:     user.ID,
			Status:     SetField(domain.StatusDeleted),
			MutedUntil: SetField[*time.Time](nil),
			UpdatedAt:  SetField(now),
			DeletedAt:  SetField(&deletedAt),
		}
		deleted, err := tx.UpdateUser(txCtx, mutation)
		if err != nil {
			return newInternalError(err)
		}
		if !validDeletedProfileMutationResult(deleted, user, now) {
			return newInternalError(nil)
		}
		if err := tx.RevokeLockedSessions(txCtx, sessionIDs, now); err != nil {
			return newInternalError(err)
		}
		if pendingAudit != nil {
			if err := tx.InsertAudit(txCtx, *pendingAudit); err != nil {
				return newInternalError(err)
			}
		}
		result.Deleted = true
		return nil
	})
	if err != nil {
		switch err {
		case ErrSessionInvalid, ErrUserFrozen:
			return DeleteMeResult{}, err
		}
		return DeleteMeResult{}, newInternalError(err)
	}
	return result, nil
}

func validProfileMutationResult(user, previous domain.User, mutation UserMutation, now time.Time) bool {
	if !validProfileUserStructure(user, mutation.UserID, false) || !user.UpdatedAt.Equal(now) {
		return false
	}
	wantDisplayName := previous.DisplayName
	if mutation.DisplayName.Set {
		wantDisplayName = mutation.DisplayName.Value
	}
	wantBio := previous.Bio
	if mutation.Bio.Set {
		wantBio = mutation.Bio.Value
	}
	if user.DisplayName != wantDisplayName || user.Bio != wantBio {
		return false
	}
	return user.ID == previous.ID && user.Email == previous.Email && user.PasswordHash == previous.PasswordHash &&
		user.Role == previous.Role && user.Status == previous.Status && optionalTimesEqual(user.MutedUntil, previous.MutedUntil) &&
		user.ViolationCount == previous.ViolationCount && user.CreatedAt.Equal(previous.CreatedAt) &&
		optionalTimesEqual(user.DeletedAt, previous.DeletedAt)
}

func validateLockedActiveSessions(sessions []domain.UserSession, userID, currentSessionID int64) (bool, []int64, error) {
	currentFound := false
	ids := make([]int64, len(sessions))
	var previousID int64
	for index, session := range sessions {
		if session.ID == currentSessionID && (session.UserID != userID || session.RevokedAt != nil) {
			return false, nil, ErrSessionInvalid
		}
		if !validAuthenticationSessionStructure(AuthenticationSession{
			ID: session.ID, UserID: session.UserID, ExpiresAt: session.ExpiresAt,
			RevokedAt: session.RevokedAt, CreatedAt: session.CreatedAt,
		}, session.ID) || session.UserID != userID || session.RevokedAt != nil {
			return false, nil, newInternalError(nil)
		}
		if index > 0 && session.ID <= previousID {
			return false, nil, newInternalError(nil)
		}
		previousID = session.ID
		ids[index] = session.ID
		if session.ID == currentSessionID {
			currentFound = true
		}
	}
	return currentFound, ids, nil
}

func validDeletedProfileMutationResult(deleted, previous domain.User, now time.Time) bool {
	return validProfileUserStructure(deleted, previous.ID, false) &&
		deleted.Status == domain.StatusDeleted && deleted.DeletedAt != nil && deleted.DeletedAt.Equal(now) &&
		deleted.MutedUntil == nil && deleted.UpdatedAt.Equal(now) && deleted.Email == previous.Email &&
		deleted.PasswordHash == previous.PasswordHash && deleted.DisplayName == previous.DisplayName &&
		deleted.Bio == previous.Bio && deleted.Role == previous.Role && deleted.ViolationCount == previous.ViolationCount &&
		deleted.CreatedAt.Equal(previous.CreatedAt)
}

func optionalTimesEqual(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
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
