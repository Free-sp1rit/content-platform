package service

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
)

// ChangeUserStatusInput contains the authenticated administrator and the
// requested status for a normal user account.
type ChangeUserStatusInput struct {
	ActorID        int64
	ActorSessionID int64
	TargetID       int64
	NewStatus      domain.Status
	Reason         string
	MutedUntil     *time.Time
	RequestID      string
}

func (s *Service) ChangeUserStatus(ctx context.Context, input ChangeUserStatusInput) (domain.UserView, error) {
	if input.ActorID <= 0 || input.ActorSessionID <= 0 || input.TargetID <= 0 {
		return domain.UserView{}, ErrSessionInvalid
	}
	if input.ActorID == input.TargetID {
		return domain.UserView{}, ErrAdminTargetForbidden
	}
	if err := profileContextError(ctx); err != nil {
		return domain.UserView{}, err
	}

	reason := strings.TrimSpace(input.Reason)
	if utf8.RuneCountInString(reason) > 1000 {
		return domain.UserView{}, newValidationError(ValidationFieldReason)
	}
	if !validAdministrativeStatus(input.NewStatus) {
		return domain.UserView{}, newValidationError(ValidationFieldStatus)
	}
	mutedUntil := normalizeStatusTime(input.MutedUntil)
	if input.NewStatus == domain.StatusMuted {
		if mutedUntil == nil || !validAuthenticationTime(*mutedUntil) {
			return domain.UserView{}, newValidationError(ValidationFieldMutedUntil)
		}
	} else if input.MutedUntil != nil {
		return domain.UserView{}, newValidationError(ValidationFieldMutedUntil)
	}

	var latest domain.User
	err := s.repository.WithinTx(ctx, func(txCtx context.Context, tx Tx) error {
		users, err := tx.LockUsers(txCtx, []int64{input.ActorID, input.TargetID})
		if err != nil {
			return newInternalError(err)
		}
		if len(users) == 0 {
			return ErrSessionInvalid
		}
		var actor, target domain.User
		actorFound, targetFound := false, false
		for _, user := range users {
			switch user.ID {
			case input.ActorID:
				actor = user
				actorFound = true
			case input.TargetID:
				target = user
				targetFound = true
			default:
				return newInternalError(nil)
			}
		}
		if !actorFound {
			return ErrSessionInvalid
		}
		var session domain.UserSession
		var targetSessions []domain.UserSession
		banningNoOp := targetFound && target.Status == domain.StatusBanned && target.MutedUntil == nil
		if input.NewStatus == domain.StatusBanned && !banningNoOp {
			lockedSessions, lockErr := tx.LockSessions(txCtx, SessionLockRequest{
				SessionIDs: []int64{input.ActorSessionID}, ActiveUserIDs: []int64{input.TargetID},
			})
			if lockErr != nil {
				return newInternalError(lockErr)
			}
			session, targetSessions, err = validateAdministrativeSessionSet(
				lockedSessions, input.ActorID, input.ActorSessionID, input.TargetID,
			)
			if err != nil {
				return err
			}
		} else {
			session, err = tx.LockSession(txCtx, input.ActorSessionID)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					return ErrSessionInvalid
				}
				return newInternalError(err)
			}
		}
		now, err := s.now()
		if err != nil {
			return err
		}
		if input.NewStatus == domain.StatusMuted && !mutedUntil.After(now) {
			return newValidationError(ValidationFieldMutedUntil)
		}
		if !validAuthenticationSessionStructure(AuthenticationSession{
			ID: session.ID, UserID: session.UserID, ExpiresAt: session.ExpiresAt,
			RevokedAt: session.RevokedAt, CreatedAt: session.CreatedAt,
		}, input.ActorSessionID) || session.UserID != input.ActorID || session.RevokedAt != nil || !domain.NormalizeTime(session.ExpiresAt).After(now) {
			return ErrSessionInvalid
		}

		if !validProfileUserStructure(actor, input.ActorID, false) {
			return newInternalError(nil)
		}
		var actorPendingAudit *AuditEntry
		if shouldRecoverExpiredMute(actor, now) {
			actor, actorPendingAudit, err = recoverExpiredMuteForAuth(txCtx, tx, actor, now, input.RequestID)
			if err != nil {
				return err
			}
		}
		if err := validateStatusActor(actor); err != nil {
			return err
		}
		if !targetFound {
			return ErrUserNotFound
		}

		if target.DeletedAt != nil {
			return ErrInvalidStatusTransition
		}
		switch target.Role {
		case domain.RoleAdmin:
			return ErrAdminTargetForbidden
		case domain.RoleUser:
		default:
			return newInternalError(nil)
		}
		switch target.Status {
		case domain.StatusPending, domain.StatusActive, domain.StatusMuted, domain.StatusFrozen, domain.StatusBanned:
		default:
			return newInternalError(nil)
		}
		if !validProfileUserStructure(target, input.TargetID, false) {
			return newInternalError(nil)
		}

		var pendingAudit *AuditEntry
		if shouldRecoverExpiredMute(target, now) {
			target, pendingAudit, err = recoverExpiredMuteForAuth(txCtx, tx, target, now, input.RequestID)
			if err != nil {
				return err
			}
		}
		if !validProfileUserStructure(target, input.TargetID, false) {
			return newInternalError(nil)
		}
		if target.Status == input.NewStatus && optionalTimesEqual(target.MutedUntil, mutedUntil) {
			if err := insertPendingStatusAudits(txCtx, tx, actorPendingAudit, pendingAudit); err != nil {
				return err
			}
			latest = secretFreeUser(target)
			return nil
		}
		if !validAdministrativeTransition(target.Status, input.NewStatus) {
			return ErrInvalidStatusTransition
		}

		previous := target
		mutation := UserMutation{
			UserID:     target.ID,
			Status:     SetField(input.NewStatus),
			MutedUntil: SetField(mutedUntil),
			UpdatedAt:  SetField(now),
		}
		target, err = tx.UpdateUser(txCtx, mutation)
		if err != nil {
			return newInternalError(err)
		}
		if !validStatusMutationResult(target, previous, mutation, now) {
			return newInternalError(nil)
		}
		if input.NewStatus == domain.StatusBanned && len(targetSessions) > 0 {
			sessionIDs := make([]int64, len(targetSessions))
			for i, session := range targetSessions {
				sessionIDs[i] = session.ID
			}
			if err := tx.RevokeLockedSessions(txCtx, sessionIDs, now); err != nil {
				return newInternalError(err)
			}
		}
		if err := insertPendingStatusAudits(txCtx, tx, actorPendingAudit, pendingAudit); err != nil {
			return err
		}
		actorID := input.ActorID
		if err := tx.InsertAudit(txCtx, AuditEntry{
			ActorType: AuditActorAdmin, ActorID: &actorID, Action: "user.status_changed",
			TargetType: "user", TargetID: target.ID, CreatedAt: now,
			Detail: map[string]any{
				"old_status": previous.Status, "new_status": target.Status,
				"reason": reason, "old_muted_until": previous.MutedUntil,
				"new_muted_until": target.MutedUntil, "request_id": input.RequestID,
			},
		}); err != nil {
			return newInternalError(err)
		}
		latest = secretFreeUser(target)
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrAdminRequired), errors.Is(err, ErrAdminTargetForbidden),
			errors.Is(err, ErrInvalidStatusTransition), errors.Is(err, ErrUserFrozen),
			errors.Is(err, ErrSessionInvalid), errors.Is(err, ErrUserNotFound),
			errors.Is(err, ErrValidationFailed):
			return domain.UserView{}, err
		}
		return domain.UserView{}, newInternalError(err)
	}
	if !validProfileUserStructure(latest, input.TargetID, true) {
		return domain.UserView{}, newInternalError(nil)
	}
	return latest.View(), nil
}

func insertPendingStatusAudits(ctx context.Context, tx Tx, audits ...*AuditEntry) error {
	pending := make([]*AuditEntry, 0, len(audits))
	for _, audit := range audits {
		if audit != nil {
			pending = append(pending, audit)
		}
	}
	sort.SliceStable(pending, func(i, j int) bool { return pending[i].TargetID < pending[j].TargetID })
	for _, audit := range pending {
		if err := tx.InsertAudit(ctx, *audit); err != nil {
			return newInternalError(err)
		}
	}
	return nil
}

func validAdministrativeStatus(status domain.Status) bool {
	switch status {
	case domain.StatusActive, domain.StatusMuted, domain.StatusFrozen, domain.StatusBanned:
		return true
	default:
		return false
	}
}

func validAdministrativeTransition(old, next domain.Status) bool {
	if old == domain.StatusPending || old == domain.StatusBanned {
		return next == domain.StatusActive || old == next
	}
	return true
}

func validateStatusActor(actor domain.User) error {
	if actor.DeletedAt != nil || actor.Status == domain.StatusBanned || actor.Status == domain.StatusDeleted {
		return ErrSessionInvalid
	}
	if actor.Role != domain.RoleAdmin {
		return ErrAdminRequired
	}
	if actor.Status == domain.StatusFrozen {
		return ErrUserFrozen
	}
	return nil
}

func normalizeStatusTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := domain.NormalizeTime(*value)
	return &normalized
}

func validStatusMutationResult(updated, previous domain.User, mutation UserMutation, now time.Time) bool {
	return validProfileUserStructure(updated, previous.ID, false) && updated.PasswordHash == previous.PasswordHash &&
		updated.Email == previous.Email && updated.DisplayName == previous.DisplayName && updated.Bio == previous.Bio &&
		updated.Role == previous.Role && updated.ViolationCount == previous.ViolationCount && updated.CreatedAt.Equal(previous.CreatedAt) &&
		updated.Status == mutation.Status.Value && optionalTimesEqual(updated.MutedUntil, mutation.MutedUntil.Value) && updated.UpdatedAt.Equal(now)
}

func validateAdministrativeSessionSet(
	sessions []domain.UserSession,
	actorID int64,
	actorSessionID int64,
	targetID int64,
) (domain.UserSession, []domain.UserSession, error) {
	var actorSession domain.UserSession
	targetSessions := make([]domain.UserSession, 0, len(sessions))
	var previousID int64
	for index, session := range sessions {
		if session.ID <= 0 || (index > 0 && session.ID <= previousID) {
			return domain.UserSession{}, nil, newInternalError(nil)
		}
		previousID = session.ID
		if !validAuthenticationSessionStructure(AuthenticationSession{
			ID: session.ID, UserID: session.UserID, ExpiresAt: session.ExpiresAt,
			RevokedAt: session.RevokedAt, CreatedAt: session.CreatedAt,
		}, session.ID) {
			return domain.UserSession{}, nil, newInternalError(nil)
		}
		if session.ID == actorSessionID {
			if actorSession.ID != 0 {
				return domain.UserSession{}, nil, newInternalError(nil)
			}
			if session.UserID != actorID {
				return domain.UserSession{}, nil, ErrSessionInvalid
			}
			actorSession = session
			continue
		}
		if session.UserID != targetID || session.RevokedAt != nil {
			return domain.UserSession{}, nil, newInternalError(nil)
		}
		targetSessions = append(targetSessions, session)
	}
	if actorSession.ID == 0 {
		return domain.UserSession{}, nil, ErrSessionInvalid
	}
	return actorSession, targetSessions, nil
}
