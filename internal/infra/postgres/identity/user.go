package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	"github.com/jackc/pgx/v5/pgconn"
)

const userColumns = `
	id, email, password_hash, display_name, bio, role, status, muted_until,
	violation_count, created_at, updated_at, deleted_at`

type rowScanner interface {
	Scan(...any) error
}

func (r *Repository) CreateUser(ctx context.Context, record identityservice.CreateUserRecord) (domain.User, error) {
	row := r.db.QueryRowContext(ctx, `
		INSERT INTO users (
			email, password_hash, display_name, bio, role, status, muted_until,
			violation_count, created_at, updated_at, deleted_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING `+userColumns,
		record.Email,
		record.PasswordHash,
		record.DisplayName,
		record.Bio,
		record.Role,
		record.Status,
		record.MutedUntil,
		record.ViolationCount,
		record.CreatedAt,
		record.UpdatedAt,
		record.DeletedAt,
	)
	user, err := scanUser(row)
	if err == nil {
		return user, nil
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" && postgresError.ConstraintName == "users_email_uidx" {
		return domain.User{}, identityservice.ErrEmailExists
	}
	return domain.User{}, repositoryInternalError(ctx, "create user", err)
}

func (r *Repository) FindLoginCredential(ctx context.Context, email string) (identityservice.LoginCredential, error) {
	var credential identityservice.LoginCredential
	err := r.db.QueryRowContext(ctx, `
		SELECT id, password_hash, status, deleted_at
		FROM users
		WHERE email = $1`, email,
	).Scan(&credential.UserID, &credential.PasswordHash, &credential.Status, &credential.DeletedAt)
	if err != nil {
		return identityservice.LoginCredential{}, classifyLookupError(ctx, "find login credential", err)
	}
	return credential, nil
}

func (r *Repository) FindUser(ctx context.Context, userID int64) (domain.User, error) {
	user, err := scanUser(r.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, userID))
	if err != nil {
		return domain.User{}, classifyLookupError(ctx, "find user", err)
	}
	return user, nil
}

func (t *transaction) LockUsers(ctx context.Context, userIDs []int64) ([]identityservice.LockedUser, error) {
	orderedIDs := sortedUniqueIDs(userIDs)
	if len(orderedIDs) == 0 {
		return []identityservice.LockedUser{}, nil
	}
	arguments := make([]any, len(orderedIDs))
	for index, id := range orderedIDs {
		arguments[index] = id
	}
	rows, err := t.tx.QueryContext(ctx, `
		SELECT `+userColumns+`
		FROM users
		WHERE id IN (`+placeholders(1, len(arguments))+`)
		ORDER BY id
		FOR UPDATE`, arguments...)
	if err != nil {
		return nil, repositoryInternalError(ctx, "lock users", err)
	}
	defer rows.Close()

	users := make([]identityservice.LockedUser, 0, len(orderedIDs))
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, repositoryInternalError(ctx, "scan locked user", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, repositoryInternalError(ctx, "iterate locked users", err)
	}
	return users, nil
}

func (t *transaction) UpdateUser(ctx context.Context, mutation identityservice.UserMutation) (domain.User, error) {
	user, err := scanUser(t.tx.QueryRowContext(ctx, `
		UPDATE users
		SET display_name = CASE WHEN $2::boolean THEN $3::text ELSE display_name END,
		    bio = CASE WHEN $4::boolean THEN $5::text ELSE bio END,
		    status = CASE WHEN $6::boolean THEN $7::text ELSE status END,
		    muted_until = CASE WHEN $8::boolean THEN $9::timestamptz ELSE muted_until END,
		    violation_count = CASE WHEN $10::boolean THEN $11::integer ELSE violation_count END,
		    updated_at = CASE WHEN $12::boolean THEN $13::timestamptz ELSE updated_at END,
		    deleted_at = CASE WHEN $14::boolean THEN $15::timestamptz ELSE deleted_at END
		WHERE id = $1
		RETURNING `+userColumns,
		mutation.UserID,
		mutation.DisplayName.Set, mutation.DisplayName.Value,
		mutation.Bio.Set, mutation.Bio.Value,
		mutation.Status.Set, mutation.Status.Value,
		mutation.MutedUntil.Set, mutation.MutedUntil.Value,
		mutation.ViolationCount.Set, mutation.ViolationCount.Value,
		mutation.UpdatedAt.Set, mutation.UpdatedAt.Value,
		mutation.DeletedAt.Set, mutation.DeletedAt.Value,
	))
	if err != nil {
		return domain.User{}, classifyLookupError(ctx, "update user", err)
	}
	return user, nil
}

func (t *transaction) RecoverExpiredMute(ctx context.Context, userID int64, now time.Time) (domain.User, bool, error) {
	user, err := scanUser(t.tx.QueryRowContext(ctx, `
		UPDATE users
		SET status = 'active', muted_until = NULL, updated_at = $2
		WHERE id = $1
		  AND status = 'muted'
		  AND muted_until <= $2
		RETURNING `+userColumns, userID, now))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, false, nil
	}
	if err != nil {
		return domain.User{}, false, repositoryInternalError(ctx, "recover expired mute", err)
	}
	return user, true, nil
}

func scanUser(scanner rowScanner) (domain.User, error) {
	var user domain.User
	err := scanner.Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.DisplayName,
		&user.Bio,
		&user.Role,
		&user.Status,
		&user.MutedUntil,
		&user.ViolationCount,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)
	return user, err
}

func classifyLookupError(ctx context.Context, operation string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return identityservice.ErrNotFound
	}
	return repositoryInternalError(ctx, operation, err)
}

func oneRowAffected(ctx context.Context, operation string, affected sql.Result) error {
	rows, err := affected.RowsAffected()
	if err != nil {
		return repositoryInternalError(ctx, operation, err)
	}
	if rows == 0 {
		return identityservice.ErrNotFound
	}
	if rows != 1 {
		return repositoryInternalError(ctx, operation, fmt.Errorf("unexpected affected row count: %d", rows))
	}
	return nil
}
