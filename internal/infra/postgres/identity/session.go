package identity

import (
	"context"
	"strings"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
)

const sessionColumns = `id, user_id, token_hash, expires_at, revoked_at, created_at`

func (r *Repository) FindSessionOwner(ctx context.Context, sessionID int64) (int64, error) {
	var userID int64
	if err := r.db.QueryRowContext(ctx, `SELECT user_id FROM user_sessions WHERE id = $1`, sessionID).Scan(&userID); err != nil {
		return 0, classifyLookupError(ctx, "find session owner", err)
	}
	return userID, nil
}

func (r *Repository) RevokeSession(ctx context.Context, request identityservice.RevokeSessionRequest) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE user_sessions
		SET revoked_at = $3
		WHERE id = $1
		  AND user_id = $2
		  AND revoked_at IS NULL`, request.SessionID, request.UserID, request.RevokedAt)
	if err != nil {
		return repositoryInternalError(ctx, "revoke session", err)
	}
	return nil
}

func (t *transaction) LockSession(ctx context.Context, sessionID int64) (domain.UserSession, error) {
	sessions, err := t.LockSessions(ctx, identityservice.SessionLockRequest{SessionIDs: []int64{sessionID}})
	if err != nil {
		return domain.UserSession{}, err
	}
	if len(sessions) == 0 {
		return domain.UserSession{}, identityservice.ErrNotFound
	}
	return sessions[0], nil
}

func (t *transaction) LockActiveSessions(ctx context.Context, userID int64) ([]domain.UserSession, error) {
	return t.LockSessions(ctx, identityservice.SessionLockRequest{ActiveUserIDs: []int64{userID}})
}

func (t *transaction) LockSessions(ctx context.Context, request identityservice.SessionLockRequest) ([]domain.UserSession, error) {
	sessionIDs := sortedUniqueIDs(request.SessionIDs)
	activeUserIDs := sortedUniqueIDs(request.ActiveUserIDs)
	if len(sessionIDs) == 0 && len(activeUserIDs) == 0 {
		return []domain.UserSession{}, nil
	}

	arguments := make([]any, 0, len(sessionIDs)+len(activeUserIDs))
	conditions := make([]string, 0, 2)
	if len(sessionIDs) > 0 {
		conditions = append(conditions, "id IN ("+placeholders(len(arguments)+1, len(sessionIDs))+")")
		for _, sessionID := range sessionIDs {
			arguments = append(arguments, sessionID)
		}
	}
	if len(activeUserIDs) > 0 {
		conditions = append(conditions, "(user_id IN ("+placeholders(len(arguments)+1, len(activeUserIDs))+") AND revoked_at IS NULL)")
		for _, userID := range activeUserIDs {
			arguments = append(arguments, userID)
		}
	}

	rows, err := t.tx.QueryContext(ctx, lockSessionsQuery(strings.Join(conditions, " OR ")), arguments...)
	if err != nil {
		return nil, repositoryInternalError(ctx, "lock sessions", err)
	}
	defer rows.Close()

	sessions := make([]domain.UserSession, 0)
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, repositoryInternalError(ctx, "scan locked session", err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, repositoryInternalError(ctx, "iterate locked sessions", err)
	}
	return sessions, nil
}

func lockSessionsQuery(conditions string) string {
	return `
		WITH locked_sessions AS (
			SELECT ` + sessionColumns + `
			FROM user_sessions
			WHERE ` + conditions + `
			ORDER BY id
			FOR UPDATE
		)
		SELECT ` + sessionColumns + `
		FROM locked_sessions
		ORDER BY id`
}

func (t *transaction) CreateSession(ctx context.Context, record identityservice.CreateSessionRecord) (domain.UserSession, error) {
	session, err := scanSession(t.tx.QueryRowContext(ctx, `
		INSERT INTO user_sessions (user_id, token_hash, expires_at, revoked_at, created_at)
		VALUES ($1, $2, $3, NULL, $4)
		RETURNING `+sessionColumns,
		record.UserID, record.TokenHash[:], record.ExpiresAt, record.CreatedAt,
	))
	if err != nil {
		return domain.UserSession{}, repositoryInternalError(ctx, "create session", err)
	}
	return session, nil
}

func (t *transaction) RotateSessionToken(ctx context.Context, sessionID int64, tokenHash [32]byte) error {
	result, err := t.tx.ExecContext(ctx, `UPDATE user_sessions SET token_hash = $2 WHERE id = $1`, sessionID, tokenHash[:])
	if err != nil {
		return repositoryInternalError(ctx, "rotate session token", err)
	}
	return oneRowAffected(ctx, "rotate session token", result)
}

func (t *transaction) RevokeLockedSessions(ctx context.Context, sessionIDs []int64, revokedAt time.Time) error {
	for _, sessionID := range sortedUniqueIDs(sessionIDs) {
		if _, err := t.tx.ExecContext(ctx, `
			UPDATE user_sessions
			SET revoked_at = $2
			WHERE id = $1
			  AND revoked_at IS NULL`, sessionID, revokedAt); err != nil {
			return repositoryInternalError(ctx, "revoke locked sessions", err)
		}
	}
	return nil
}

func scanSession(scanner rowScanner) (domain.UserSession, error) {
	var session domain.UserSession
	err := scanner.Scan(
		&session.ID,
		&session.UserID,
		&session.TokenHash,
		&session.ExpiresAt,
		&session.RevokedAt,
		&session.CreatedAt,
	)
	return session, err
}
