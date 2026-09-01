package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSortedUniqueIDsOrdersDeduplicatesAndPreservesInput(t *testing.T) {
	input := []int64{9, 3, 9, 1, 3, 7}
	original := append([]int64(nil), input...)

	got := sortedUniqueIDs(input)

	if want := []int64{1, 3, 7, 9}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sortedUniqueIDs(%v) = %v, want %v", input, got, want)
	}
	if !reflect.DeepEqual(input, original) {
		t.Fatalf("sortedUniqueIDs() mutated caller input: got %v, want %v", input, original)
	}
	if got := sortedUniqueIDs(nil); got != nil {
		t.Fatalf("sortedUniqueIDs(nil) = %v, want nil", got)
	}
}

func TestRollbackFailureErrorHidesCallbackAndDriverCauses(t *testing.T) {
	callbackErr := errors.New("callback secret token")
	rollbackErr := errors.New("driver SQL rollback detail")

	err := rollbackFailureError(context.Background(), callbackErr, rollbackErr)

	if !errors.Is(err, identityservice.ErrInternal) {
		t.Fatal("rollbackFailureError() did not expose ErrInternal")
	}
	if errors.Is(err, callbackErr) || errors.Is(err, rollbackErr) {
		t.Fatal("rollbackFailureError() exposed a private cause through errors.Is")
	}
	var safeInternal *internalError
	if !errors.As(err, &safeInternal) {
		t.Fatalf("rollbackFailureError() type = %T, want infra-private internalError", err)
	}
	message := strings.ToLower(err.Error())
	for _, forbidden := range []string{"secret", "token", "driver", "sql", "rollback detail"} {
		if strings.Contains(message, forbidden) {
			t.Fatal("rollbackFailureError() leaked private cause text")
		}
	}
}

func TestRepositoryInternalErrorExposesOnlyStableAndContextClassifications(t *testing.T) {
	cause := &secretDriverError{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := repositoryInternalError(ctx, "query identity row", cause)

	if !errors.Is(err, identityservice.ErrInternal) {
		t.Fatal("repositoryInternalError() did not expose ErrInternal")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal("repositoryInternalError() did not expose context.Canceled classification")
	}
	if errors.Is(err, cause) {
		t.Fatal("repositoryInternalError() exposed raw driver cause through errors.Is")
	}
	var leaked *secretDriverError
	if errors.As(err, &leaked) {
		t.Fatalf("repositoryInternalError() exposed raw driver cause through errors.As")
	}
	var safeInternal *internalError
	if !errors.As(err, &safeInternal) {
		t.Fatalf("repositoryInternalError() type = %T, want infra-private internalError", err)
	}
	for _, forbidden := range []string{"secret", "driver", "constraint", "sqlstate"} {
		if strings.Contains(strings.ToLower(err.Error()), forbidden) {
			t.Fatal("repositoryInternalError() leaked raw driver text")
		}
	}

	deadlineErr := repositoryInternalError(
		context.Background(),
		"query identity row",
		errors.Join(cause, context.DeadlineExceeded),
	)
	if !errors.Is(deadlineErr, identityservice.ErrInternal) {
		t.Fatal("repositoryInternalError() with deadline did not expose ErrInternal")
	}
	if !errors.Is(deadlineErr, context.DeadlineExceeded) {
		t.Fatal("repositoryInternalError() did not expose context.DeadlineExceeded classification")
	}
	if errors.Is(deadlineErr, cause) {
		t.Fatal("repositoryInternalError() with deadline exposed raw driver cause")
	}
}

func TestRepositoryInternalErrorFormattingNeverLeaksDriverCause(t *testing.T) {
	driverCause := &pgconn.PgError{
		Code:           "23505",
		Message:        "secret SQL constraint detail",
		ConstraintName: "users_email_uidx",
	}
	err := repositoryInternalError(context.Background(), "query identity row", driverCause)
	forbidden := []string{
		"secret",
		"sql",
		"constraint",
		"23505",
		"users_email_uidx",
		"pgconn",
		"pgerror",
	}

	for _, format := range []string{"%v", "%+v", "%#v", "%q"} {
		assertSafeRenderedError(t, "fmt "+format, fmt.Sprintf(format, err), forbidden)
	}

	encoded, marshalErr := json.Marshal(map[string]any{"error": err})
	if marshalErr != nil {
		t.Fatal("marshal repository error for safety check failed")
	}
	assertSafeRenderedError(t, "encoding/json", string(encoded), forbidden)

	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Error("repository operation failed", slog.Any("error", err))
	assertSafeRenderedError(t, "slog JSON", logged.String(), forbidden)

	var leaked *pgconn.PgError
	if errors.As(err, &leaked) {
		t.Fatal("repositoryInternalError() exposed PostgreSQL cause through errors.As")
	}
}

func TestEncodeAuditDetailUsesInfraPrivateSafeError(t *testing.T) {
	_, err := encodeAuditDetail(context.Background(), map[string]any{
		"secret_refresh_hash": func() {},
	})

	if !errors.Is(err, identityservice.ErrInternal) {
		t.Fatal("encodeAuditDetail() did not expose ErrInternal")
	}
	var safeInternal *internalError
	if !errors.As(err, &safeInternal) {
		t.Fatalf("encodeAuditDetail() type = %T, want infra-private internalError", err)
	}
	for _, forbidden := range []string{"secret", "refresh", "hash", "func"} {
		if strings.Contains(strings.ToLower(err.Error()), forbidden) {
			t.Fatal("encodeAuditDetail() leaked audit detail or marshal cause text")
		}
	}
}

type secretDriverError struct{}

func (*secretDriverError) Error() string {
	return "secret driver constraint SQLSTATE 99999"
}

func assertSafeRenderedError(t *testing.T, presentation, rendered string, forbidden []string) {
	t.Helper()
	lowerRendered := strings.ToLower(rendered)
	for _, value := range forbidden {
		if strings.Contains(lowerRendered, strings.ToLower(value)) {
			t.Fatalf("%s representation leaked a forbidden driver detail", presentation)
		}
	}
}
