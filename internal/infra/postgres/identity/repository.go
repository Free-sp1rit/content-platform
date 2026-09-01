package identity

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"

	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
)

type Repository struct {
	db *sql.DB
}

type transaction struct {
	tx *sql.Tx
}

type internalError struct {
	operation  string
	contextErr error
}

var (
	_ identityservice.Repository = (*Repository)(nil)
	_ identityservice.Tx         = (*transaction)(nil)
)

func New(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) WithinTx(ctx context.Context, callback func(context.Context, identityservice.Tx) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return repositoryInternalError(ctx, "begin identity transaction", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := callback(ctx, &transaction{tx: tx}); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return rollbackFailureError(ctx, err, rollbackErr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return repositoryInternalError(ctx, "commit identity transaction", err)
	}
	return nil
}

func rollbackFailureError(ctx context.Context, callbackErr, rollbackErr error) error {
	return repositoryInternalError(ctx, "roll back identity transaction", errors.Join(callbackErr, rollbackErr))
}

func repositoryInternalError(ctx context.Context, operation string, err error) error {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		operation = "identity repository operation"
	}
	return &internalError{
		operation:  operation,
		contextErr: repositoryContextError(ctx, err),
	}
}

func repositoryContextError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		switch {
		case errors.Is(contextErr, context.Canceled):
			return context.Canceled
		case errors.Is(contextErr, context.DeadlineExceeded):
			return context.DeadlineExceeded
		}
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

func (e *internalError) Error() string {
	return e.operation + ": " + identityservice.ErrInternal.Error()
}

func (e *internalError) Unwrap() error {
	return identityservice.ErrInternal
}

func (e *internalError) Is(target error) bool {
	if target == identityservice.ErrInternal {
		return true
	}
	if target == context.Canceled || target == context.DeadlineExceeded {
		return e.contextErr == target
	}
	return false
}

func sortedUniqueIDs(ids []int64) []int64 {
	if len(ids) == 0 {
		return nil
	}
	ordered := append([]int64(nil), ids...)
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left] < ordered[right]
	})
	unique := ordered[:0]
	for _, id := range ordered {
		if len(unique) == 0 || unique[len(unique)-1] != id {
			unique = append(unique, id)
		}
	}
	return unique
}

func placeholders(start, count int) string {
	if count == 0 {
		return ""
	}
	result := make([]byte, 0, count*4)
	for index := 0; index < count; index++ {
		if index > 0 {
			result = append(result, ',', ' ')
		}
		result = append(result, '$')
		result = appendInt(result, start+index)
	}
	return string(result)
}

func appendInt(destination []byte, value int) []byte {
	if value >= 10 {
		destination = appendInt(destination, value/10)
	}
	return append(destination, byte('0'+value%10))
}
