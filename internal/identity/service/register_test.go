package service

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
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
)

func TestRegisterNormalizesAndPersistsFixedUserRecord(t *testing.T) {
	location := time.FixedZone("UTC+08", 8*60*60)
	clockTime := time.Date(2026, time.September, 2, 19, 20, 21, 987654321, location)
	svc, fixture := newRegisterFixture(t, clockTime)
	ctx := context.WithValue(context.Background(), registerContextKey{}, "registration-request")

	_, err := svc.Register(ctx, RegisterInput{
		Email:       " User@Example.COM ",
		Password:    "password",
		DisplayName: " Alice ",
	})
	if err != nil {
		t.Fatalf("Register() returned error type %T", err)
	}

	wantTime := time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC)
	assertExactCreateUserRecord(t, fixture.repository.record, fixture.hasher.hashResult, wantTime)
	if fixture.repository.ctx.Value(registerContextKey{}) != "registration-request" {
		t.Fatal("Register() did not propagate context to Repository.CreateUser")
	}
	if got, want := fixture.events, []string{"hash", "clock", "create"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Register() dependency order = %v, want %v", got, want)
	}
}

func TestRegisterPassesOriginalPasswordToHasherExactlyOnce(t *testing.T) {
	const originalPassword = " pass12 "
	if len(originalPassword) != 8 {
		t.Fatal("password fixture must exercise the exact 8-byte boundary")
	}
	svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:       "user@example.com",
		Password:    originalPassword,
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("Register() returned error type %T", err)
	}

	if fixture.hasher.hashCalls != 1 {
		t.Fatalf("PasswordHasher.Hash() calls = %d, want 1", fixture.hasher.hashCalls)
	}
	if fixture.hasher.candidate != originalPassword {
		t.Fatal("Register() changed the password before PasswordHasher.Hash")
	}
	if fixture.repository.record.PasswordHash != fixture.hasher.hashResult {
		t.Fatal("Register() did not persist the hash returned by PasswordHasher.Hash")
	}
	if fixture.hasher.compareCalls != 0 || fixture.hasher.dummyHashCalls != 0 || fixture.hasher.dummyCandidateCalls != 0 {
		t.Fatal("Register() invoked a non-Hash PasswordHasher operation")
	}
}

func TestRegisterReturnsExactSafeUserViewWithoutSessionOrTokens(t *testing.T) {
	now := time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC)
	svc, fixture := newRegisterFixture(t, now)

	got, err := svc.Register(context.Background(), RegisterInput{
		Email:       "user@example.com",
		Password:    "password",
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("Register() returned error type %T", err)
	}

	assertExactRegisteredUserView(t, got, fixture.repository.createdUserID, now)
	assertUserViewContainsNoRegistrationSecrets(t, got, fixture.hasher.hashResult, "password")
	if fixture.repository.withinTxCalls != 0 {
		t.Fatalf("Repository.WithinTx() calls = %d, want 0", fixture.repository.withinTxCalls)
	}
	if fixture.accessTokens.totalCalls() != 0 {
		t.Fatalf("AccessTokenManager calls = %d, want 0", fixture.accessTokens.totalCalls())
	}
	if fixture.refreshTokens.totalCalls() != 0 {
		t.Fatalf("RefreshTokenGenerator calls = %d, want 0", fixture.refreshTokens.totalCalls())
	}
}

func TestRegisterAcceptsUTF8PasswordByteBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{name: "8 UTF-8 bytes", password: "界界ab"},
		{name: "72 UTF-8 bytes", password: strings.Repeat("界", 24)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))

			_, err := svc.Register(context.Background(), RegisterInput{
				Email:       "user@example.com",
				Password:    tt.password,
				DisplayName: "Alice",
			})
			if err != nil {
				t.Fatalf("Register() returned error type %T", err)
			}
			if fixture.hasher.hashCalls != 1 {
				t.Fatalf("PasswordHasher.Hash() calls = %d, want 1", fixture.hasher.hashCalls)
			}
			if fixture.hasher.candidate != tt.password {
				t.Fatal("Register() changed a boundary password before hashing")
			}
			if fixture.repository.createCalls != 1 {
				t.Fatalf("Repository.CreateUser() calls = %d, want 1", fixture.repository.createCalls)
			}
		})
	}
}

func TestRegisterRejectsInvalidFieldsBeforeCallingDependencies(t *testing.T) {
	tests := []struct {
		name      string
		input     RegisterInput
		wantField ValidationField
	}{
		{
			name: "invalid email",
			input: RegisterInput{
				Email:       "definitely-not-an-address",
				Password:    "password",
				DisplayName: "Alice",
			},
			wantField: ValidationFieldEmail,
		},
		{
			name: "password below 8 bytes",
			input: RegisterInput{
				Email:       "user@example.com",
				Password:    strings.Repeat("p", 7),
				DisplayName: "Alice",
			},
			wantField: ValidationFieldPassword,
		},
		{
			name: "password above 72 bytes",
			input: RegisterInput{
				Email:       "user@example.com",
				Password:    strings.Repeat("界", 24) + "a",
				DisplayName: "Alice",
			},
			wantField: ValidationFieldPassword,
		},
		{
			name: "empty normalized display name",
			input: RegisterInput{
				Email:       "user@example.com",
				Password:    "password",
				DisplayName: " \t\n ",
			},
			wantField: ValidationFieldDisplayName,
		},
		{
			name: "display name above 100 runes",
			input: RegisterInput{
				Email:       "user@example.com",
				Password:    "password",
				DisplayName: strings.Repeat("界", 101),
			},
			wantField: ValidationFieldDisplayName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))

			got, err := svc.Register(context.Background(), tt.input)

			assertRegistrationValidationError(t, err, tt.wantField)
			if got != (domain.UserView{}) {
				t.Fatal("Register() returned a non-zero user view after validation failure")
			}
			if fixture.hasher.hashCalls != 0 {
				t.Fatalf("PasswordHasher.Hash() calls = %d, want 0", fixture.hasher.hashCalls)
			}
			if fixture.clock.calls != 0 {
				t.Fatalf("Clock.Now() calls = %d, want 0", fixture.clock.calls)
			}
			if fixture.repository.createCalls != 0 {
				t.Fatalf("Repository.CreateUser() calls = %d, want 0", fixture.repository.createCalls)
			}
		})
	}
}

func TestValidationErrorFieldIsReadOnly(t *testing.T) {
	validationType := reflect.TypeOf(ValidationError{})
	if validationType.NumField() != 1 {
		t.Fatalf("ValidationError field count = %d, want 1", validationType.NumField())
	}
	if field := validationType.Field(0); field.IsExported() {
		t.Fatal("ValidationError exposes a mutable public field")
	}
	method, ok := reflect.TypeOf((*ValidationError)(nil)).MethodByName("Field")
	if !ok {
		t.Fatal("ValidationError does not expose the read-only Field accessor")
	}
	if method.Type.NumIn() != 1 || method.Type.NumOut() != 1 || method.Type.Out(0) != reflect.TypeOf(ValidationField("")) {
		t.Fatal("ValidationError.Field has an unstable API shape")
	}
}

func TestRegisterMapsHasherFailureToSafeInternalError(t *testing.T) {
	privateCause := errors.New("bcrypt failure with private candidate and hash detail")
	svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))
	fixture.hasher.hashErr = privateCause
	const originalPassword = "password"

	got, err := svc.Register(context.Background(), RegisterInput{
		Email:       "user@example.com",
		Password:    originalPassword,
		DisplayName: "Alice",
	})

	assertRegistrationInternalError(t, err)
	if errors.Is(err, privateCause) {
		t.Fatal("Register() exposed the PasswordHasher cause through errors.Is")
	}
	assertErrorTextOmitsPrivateValues(t, err, originalPassword, privateCause.Error(), fixture.hasher.hashResult)
	if got != (domain.UserView{}) {
		t.Fatal("Register() returned a non-zero user view after hashing failure")
	}
	if fixture.hasher.hashCalls != 1 {
		t.Fatalf("PasswordHasher.Hash() calls = %d, want 1", fixture.hasher.hashCalls)
	}
	if fixture.hasher.candidate != originalPassword {
		t.Fatal("Register() changed the password before the failing hash call")
	}
	if fixture.clock.calls != 0 {
		t.Fatalf("Clock.Now() calls = %d, want 0", fixture.clock.calls)
	}
	if fixture.repository.createCalls != 0 {
		t.Fatalf("Repository.CreateUser() calls = %d, want 0", fixture.repository.createCalls)
	}
}

func TestRegisterStopsBeforeHashWhenContextAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))

	got, err := svc.Register(ctx, RegisterInput{
		Email:       "user@example.com",
		Password:    "password",
		DisplayName: "Alice",
	})

	assertRegistrationInternalError(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("Register() did not preserve the pre-hash context cancellation classification")
	}
	if got != (domain.UserView{}) {
		t.Fatal("Register() returned a non-zero user view for a canceled context")
	}
	if fixture.hasher.hashCalls != 0 || fixture.clock.calls != 0 || fixture.repository.createCalls != 0 {
		t.Fatal("Register() called a dependency after observing pre-hash context cancellation")
	}
}

func TestRegisterStopsBeforeClockAndRepositoryWhenContextCanceledDuringHash(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))
	fixture.hasher.afterHash = cancel

	got, err := svc.Register(ctx, RegisterInput{
		Email:       "user@example.com",
		Password:    "password",
		DisplayName: "Alice",
	})

	assertRegistrationInternalError(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("Register() did not preserve cancellation observed after hashing")
	}
	if got != (domain.UserView{}) {
		t.Fatal("Register() returned a non-zero user view after cancellation during hashing")
	}
	if fixture.hasher.hashCalls != 1 {
		t.Fatalf("PasswordHasher.Hash() calls = %d, want 1", fixture.hasher.hashCalls)
	}
	if fixture.clock.calls != 0 || fixture.repository.createCalls != 0 {
		t.Fatal("Register() called clock or repository after cancellation during hashing")
	}
	if got, want := fixture.events, []string{"hash"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Register() dependency order = %v, want %v", got, want)
	}
}

func TestRegisterHasherFailureRemainsDefinitiveWhenContextCancelsDuringHash(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	privateCause := &secretRegistrationDependencyError{}
	svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))
	fixture.hasher.hashErr = privateCause
	fixture.hasher.afterHash = cancel

	_, err := svc.Register(ctx, RegisterInput{
		Email:       "user@example.com",
		Password:    "password",
		DisplayName: "Alice",
	})

	assertRegistrationInternalError(t, err)
	if errors.Is(err, context.Canceled) {
		t.Fatal("Register() rewrote a definitive hasher failure using later context cancellation")
	}
	if errors.Is(err, privateCause) {
		t.Fatal("Register() exposed the private hasher cause")
	}
	assertSafeInternalErrorPresentation(t, err, privateCause)
	if fixture.clock.calls != 0 || fixture.repository.createCalls != 0 {
		t.Fatal("Register() called clock or repository after hasher failure")
	}
}

func TestRegisterAcceptsNonZeroYearZeroClockValue(t *testing.T) {
	clockTime := time.Date(0, time.January, 1, 2, 3, 4, 987654321, time.UTC)
	wantTime := domain.NormalizeTime(clockTime)
	svc, fixture := newRegisterFixture(t, clockTime)

	got, err := svc.Register(context.Background(), RegisterInput{
		Email:       "user@example.com",
		Password:    "password",
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("Register() returned error type %T for a serializable year-zero clock value", err)
	}

	if fixture.hasher.hashCalls != 1 {
		t.Fatalf("PasswordHasher.Hash() calls = %d, want 1", fixture.hasher.hashCalls)
	}
	if fixture.clock.calls != 1 {
		t.Fatalf("Clock.Now() calls = %d, want 1", fixture.clock.calls)
	}
	if fixture.repository.createCalls != 1 {
		t.Fatalf("Repository.CreateUser() calls = %d, want 1", fixture.repository.createCalls)
	}
	assertExactCreateUserRecord(t, fixture.repository.record, fixture.hasher.hashResult, wantTime)
	if fixture.repository.record.CreatedAt.Year() != 0 || fixture.repository.record.UpdatedAt.Year() != 0 {
		t.Fatal("Register() did not persist the normalized year-zero clock value")
	}
	assertExactRegisteredUserView(t, got, fixture.repository.createdUserID, wantTime)
	if _, err := json.Marshal(got); err != nil {
		t.Fatalf("json.Marshal(Register() user view) error type = %T for year zero", err)
	}
}

func TestServiceNowNormalizesClockForReuse(t *testing.T) {
	location := time.FixedZone("UTC+08", 8*60*60)
	clockTime := time.Date(2026, time.September, 2, 19, 20, 21, 987654321, location)
	svc, fixture := newRegisterFixture(t, clockTime)

	got, err := svc.now()
	if err != nil {
		t.Fatalf("Service.now() returned error type %T for a valid clock value", err)
	}
	want := time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC)
	if !got.Equal(want) || got.Location() != time.UTC || got.Nanosecond() != 0 {
		t.Fatalf("Service.now() = %v, want %v in UTC at second precision", got, want)
	}
	if fixture.clock.calls != 1 {
		t.Fatalf("Clock.Now() calls = %d, want 1", fixture.clock.calls)
	}
}

func TestRegisterRejectsInvalidClockValuesBeforePersistence(t *testing.T) {
	tests := []struct {
		name string
		now  time.Time
	}{
		{name: "zero time", now: time.Time{}},
		{name: "negative year", now: time.Date(-1, time.January, 1, 0, 0, 0, 0, time.UTC)},
		{name: "year outside safe serialization range", now: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, fixture := newRegisterFixture(t, tt.now)

			got, err := svc.Register(context.Background(), RegisterInput{
				Email:       "user@example.com",
				Password:    "password",
				DisplayName: "Alice",
			})

			assertRegistrationInternalError(t, err)
			if got != (domain.UserView{}) {
				t.Fatal("Register() returned a non-zero user view after clock failure")
			}
			if fixture.hasher.hashCalls != 1 {
				t.Fatalf("PasswordHasher.Hash() calls = %d, want 1", fixture.hasher.hashCalls)
			}
			if fixture.clock.calls != 1 {
				t.Fatalf("Clock.Now() calls = %d, want 1", fixture.clock.calls)
			}
			if fixture.repository.createCalls != 0 {
				t.Fatalf("Repository.CreateUser() calls = %d, want 0", fixture.repository.createCalls)
			}
			if got, want := fixture.events, []string{"hash", "clock"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("Register() dependency order = %v, want %v", got, want)
			}
		})
	}
}

func TestRegisterMapsDuplicateEmailToStableConflict(t *testing.T) {
	privateCause := errors.New("secret SQL unique constraint detail")
	svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))
	fixture.repository.createErr = errors.Join(ErrEmailExists, privateCause)

	got, err := svc.Register(context.Background(), RegisterInput{
		Email:       " User@Example.COM ",
		Password:    "password",
		DisplayName: "Alice",
	})

	if !errors.Is(err, ErrEmailAlreadyRegistered) {
		t.Fatalf("Register() error type = %T, want ErrEmailAlreadyRegistered", err)
	}
	if errors.Is(err, ErrEmailExists) || errors.Is(err, privateCause) {
		t.Fatal("Register() exposed a repository duplicate-email cause")
	}
	if errors.Is(err, ErrInternal) || errors.Is(err, ErrValidationFailed) {
		t.Fatal("Register() misclassified duplicate email")
	}
	if err.Error() != "email already registered" {
		t.Fatal("Register() conflict error did not expose the stable safe service message")
	}
	assertErrorTextOmitsPrivateValues(t, err, privateCause.Error(), "user@example.com", "password", fixture.hasher.hashResult)
	if got != (domain.UserView{}) {
		t.Fatal("Register() returned a non-zero user view after duplicate conflict")
	}
}

func TestRegisterMapsRepositoryFailuresToSafeInternalError(t *testing.T) {
	privateCause := &secretRegistrationDependencyError{}
	tests := []struct {
		name          string
		repositoryErr error
		privateCause  error
		contextMarker error
	}{
		{name: "repository operation", repositoryErr: privateCause, privateCause: privateCause},
		{
			name:          "context canceled",
			repositoryErr: errors.Join(privateCause, context.Canceled),
			privateCause:  privateCause,
			contextMarker: context.Canceled,
		},
		{
			name:          "deadline exceeded",
			repositoryErr: errors.Join(privateCause, context.DeadlineExceeded),
			privateCause:  privateCause,
			contextMarker: context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))
			fixture.repository.createErr = tt.repositoryErr

			got, err := svc.Register(context.Background(), RegisterInput{
				Email:       "user@example.com",
				Password:    "password",
				DisplayName: "Alice",
			})

			assertRegistrationInternalError(t, err)
			if tt.privateCause != nil && errors.Is(err, tt.privateCause) {
				t.Fatal("Register() exposed a private repository cause through errors.Is")
			}
			if tt.contextMarker != nil && !errors.Is(err, tt.contextMarker) {
				t.Fatal("Register() dropped the repository context classification")
			}
			assertSafeInternalErrorPresentation(t, err, privateCause)
			assertErrorTextOmitsPrivateValues(t, err, tt.repositoryErr.Error(), "user@example.com", "password", fixture.hasher.hashResult)
			if got != (domain.UserView{}) {
				t.Fatal("Register() returned a non-zero user view after repository failure")
			}
			if fixture.repository.createCalls != 1 {
				t.Fatalf("Repository.CreateUser() calls = %d, want 1", fixture.repository.createCalls)
			}
			if got, want := fixture.events, []string{"hash", "clock", "create"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("Register() dependency order = %v, want %v", got, want)
			}
		})
	}
}

func TestRegisterRepositoryContextFailureWinsOverDuplicateConflict(t *testing.T) {
	svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))
	fixture.repository.createErr = errors.Join(ErrEmailExists, context.Canceled)

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:       "user@example.com",
		Password:    "password",
		DisplayName: "Alice",
	})

	assertRegistrationInternalError(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("Register() dropped context cancellation from the repository error chain")
	}
	if errors.Is(err, ErrEmailAlreadyRegistered) || errors.Is(err, ErrValidationFailed) {
		t.Fatal("Register() mapped a context failure to a public client error")
	}
}

func TestRegisterDuplicateClassificationIgnoresPostResultContextCancellation(t *testing.T) {
	ctx := &postRepositoryResultContext{Context: context.Background()}
	svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))
	fixture.repository.createErr = ErrEmailExists
	fixture.repository.beforeReturn = func() {
		ctx.repositoryResultReturned = true
	}

	_, err := svc.Register(ctx, RegisterInput{
		Email:       "user@example.com",
		Password:    "password",
		DisplayName: "Alice",
	})

	if !errors.Is(err, ErrEmailAlreadyRegistered) {
		t.Fatalf("Register() error type = %T, want ErrEmailAlreadyRegistered", err)
	}
	if errors.Is(err, ErrInternal) || errors.Is(err, context.Canceled) {
		t.Fatal("Register() let post-result context cancellation rewrite duplicate classification")
	}
	if ctx.errCalls != 2 {
		t.Fatalf("context.Err() calls = %d, want only the two pre-repository checkpoints", ctx.errCalls)
	}
}

type registerContextKey struct{}

type postRepositoryResultContext struct {
	context.Context
	repositoryResultReturned bool
	errCalls                 int
}

func (c *postRepositoryResultContext) Err() error {
	c.errCalls++
	if c.repositoryResultReturned {
		return context.Canceled
	}
	return nil
}

type registerFixture struct {
	events        []string
	repository    *registerRepositorySpy
	hasher        *registerPasswordHasherSpy
	clock         *registerClockSpy
	accessTokens  *registerAccessTokenSpy
	refreshTokens *registerRefreshTokenSpy
}

func TestRegisterRejectsNilContextBeforeCallingDependencies(t *testing.T) {
	svc, fixture := newRegisterFixture(t, time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC))

	got, err := svc.Register(nil, RegisterInput{
		Email:       "user@example.com",
		Password:    "password",
		DisplayName: "Alice",
	})

	assertRegistrationInternalError(t, err)
	if got != (domain.UserView{}) {
		t.Fatal("Register() returned a non-zero user view for nil context")
	}
	if fixture.hasher.hashCalls != 0 || fixture.clock.calls != 0 || fixture.repository.createCalls != 0 {
		t.Fatal("Register() called a dependency with nil context")
	}
	if fixture.accessTokens.totalCalls() != 0 || fixture.refreshTokens.totalCalls() != 0 {
		t.Fatal("Register() generated tokens with nil context")
	}
}

func newRegisterFixture(t *testing.T, now time.Time) (*Service, *registerFixture) {
	t.Helper()

	fixture := &registerFixture{}
	fixture.repository = &registerRepositorySpy{
		events:        &fixture.events,
		createdUserID: 73,
	}
	fixture.hasher = &registerPasswordHasherSpy{
		events:     &fixture.events,
		hashResult: "$2a$12$opaque-registration-hash",
	}
	fixture.clock = &registerClockSpy{events: &fixture.events, now: now}
	fixture.accessTokens = &registerAccessTokenSpy{}
	fixture.refreshTokens = &registerRefreshTokenSpy{}

	svc, err := New(Dependencies{
		Repository:            fixture.repository,
		PasswordHasher:        fixture.hasher,
		AccessTokenManager:    fixture.accessTokens,
		RefreshTokenGenerator: fixture.refreshTokens,
		Clock:                 fixture.clock,
	}, Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New() returned error type %T for valid registration fixture", err)
	}
	return svc, fixture
}

type registerRepositorySpy struct {
	repositoryPortStub
	events        *[]string
	createCalls   int
	withinTxCalls int
	ctx           context.Context
	record        CreateUserRecord
	createdUserID int64
	createErr     error
	beforeReturn  func()
}

func (r *registerRepositorySpy) CreateUser(ctx context.Context, record CreateUserRecord) (domain.User, error) {
	r.createCalls++
	r.ctx = ctx
	r.record = record
	*r.events = append(*r.events, "create")
	if r.beforeReturn != nil {
		r.beforeReturn()
	}
	if r.createErr != nil {
		return domain.User{}, r.createErr
	}
	return domain.User{
		ID:             r.createdUserID,
		Email:          record.Email,
		PasswordHash:   record.PasswordHash,
		DisplayName:    record.DisplayName,
		Bio:            record.Bio,
		Role:           record.Role,
		Status:         record.Status,
		MutedUntil:     record.MutedUntil,
		ViolationCount: record.ViolationCount,
		CreatedAt:      record.CreatedAt,
		UpdatedAt:      record.UpdatedAt,
		DeletedAt:      record.DeletedAt,
	}, nil
}

func (r *registerRepositorySpy) WithinTx(context.Context, func(context.Context, Tx) error) error {
	r.withinTxCalls++
	return nil
}

type registerPasswordHasherSpy struct {
	events              *[]string
	hashCalls           int
	compareCalls        int
	dummyHashCalls      int
	dummyCandidateCalls int
	candidate           string
	hashResult          string
	hashErr             error
	afterHash           func()
}

func (h *registerPasswordHasherSpy) Hash(candidate string) (string, error) {
	h.hashCalls++
	h.candidate = candidate
	*h.events = append(*h.events, "hash")
	if h.afterHash != nil {
		h.afterHash()
	}
	return h.hashResult, h.hashErr
}

func (h *registerPasswordHasherSpy) Compare(string, string) (bool, error) {
	h.compareCalls++
	return false, nil
}

func (h *registerPasswordHasherSpy) DummyHash() string {
	h.dummyHashCalls++
	return ""
}

func (h *registerPasswordHasherSpy) DummyCandidate() string {
	h.dummyCandidateCalls++
	return ""
}

type registerClockSpy struct {
	events *[]string
	calls  int
	now    time.Time
}

func (c *registerClockSpy) Now() time.Time {
	c.calls++
	*c.events = append(*c.events, "clock")
	return c.now
}

type registerAccessTokenSpy struct {
	generateJWTIDCalls int
	signCalls          int
}

func (m *registerAccessTokenSpy) GenerateJWTID() (string, error) {
	m.generateJWTIDCalls++
	return "", nil
}

func (m *registerAccessTokenSpy) Sign(int64, int64, time.Time, time.Time, string) (string, error) {
	m.signCalls++
	return "", nil
}

func (m *registerAccessTokenSpy) totalCalls() int {
	return m.generateJWTIDCalls + m.signCalls
}

type registerRefreshTokenSpy struct {
	generateCalls int
	formatCalls   int
	parseCalls    int
	matchCalls    int
}

func (g *registerRefreshTokenSpy) Generate() (string, [32]byte, error) {
	g.generateCalls++
	return "", [32]byte{}, nil
}

func (g *registerRefreshTokenSpy) Format(int64, string) (string, error) {
	g.formatCalls++
	return "", nil
}

func (g *registerRefreshTokenSpy) Parse(string) (int64, [32]byte, error) {
	g.parseCalls++
	return 0, [32]byte{}, nil
}

func (g *registerRefreshTokenSpy) Match([32]byte, [32]byte) bool {
	g.matchCalls++
	return false
}

func (g *registerRefreshTokenSpy) totalCalls() int {
	return g.generateCalls + g.formatCalls + g.parseCalls + g.matchCalls
}

func assertExactCreateUserRecord(t *testing.T, got CreateUserRecord, wantHash string, wantTime time.Time) {
	t.Helper()

	if got.Email != "user@example.com" {
		t.Fatal("CreateUserRecord.Email was not normalized")
	}
	if got.PasswordHash != wantHash {
		t.Fatal("CreateUserRecord.PasswordHash did not match the hasher result")
	}
	if got.DisplayName != "Alice" {
		t.Fatal("CreateUserRecord.DisplayName was not normalized")
	}
	if got.Bio != "" {
		t.Fatal("CreateUserRecord.Bio was not the fixed empty value")
	}
	if got.Role != domain.RoleUser {
		t.Fatalf("CreateUserRecord.Role = %q, want %q", got.Role, domain.RoleUser)
	}
	if got.Status != domain.StatusActive {
		t.Fatalf("CreateUserRecord.Status = %q, want %q", got.Status, domain.StatusActive)
	}
	if got.MutedUntil != nil {
		t.Fatal("CreateUserRecord.MutedUntil must be nil")
	}
	if got.ViolationCount != 0 {
		t.Fatalf("CreateUserRecord.ViolationCount = %d, want 0", got.ViolationCount)
	}
	if !got.CreatedAt.Equal(wantTime) || got.CreatedAt.Location() != time.UTC || got.CreatedAt.Nanosecond() != 0 {
		t.Fatalf("CreateUserRecord.CreatedAt = %v, want %v in UTC at second precision", got.CreatedAt, wantTime)
	}
	if !got.UpdatedAt.Equal(wantTime) || got.UpdatedAt.Location() != time.UTC || got.UpdatedAt.Nanosecond() != 0 {
		t.Fatalf("CreateUserRecord.UpdatedAt = %v, want %v in UTC at second precision", got.UpdatedAt, wantTime)
	}
	if got.DeletedAt != nil {
		t.Fatal("CreateUserRecord.DeletedAt must be nil")
	}
}

func assertExactRegisteredUserView(t *testing.T, got domain.UserView, wantID int64, wantTime time.Time) {
	t.Helper()

	if got.ID != wantID {
		t.Fatalf("Register() user ID = %d, want %d", got.ID, wantID)
	}
	if got.Email != "user@example.com" {
		t.Fatal("Register() user email was not the normalized persisted value")
	}
	if got.DisplayName != "Alice" {
		t.Fatal("Register() display name was not the normalized persisted value")
	}
	if got.Bio != "" {
		t.Fatal("Register() bio was not the fixed empty value")
	}
	if got.Role != domain.RoleUser {
		t.Fatalf("Register() role = %q, want %q", got.Role, domain.RoleUser)
	}
	if got.Status != domain.StatusActive {
		t.Fatalf("Register() status = %q, want %q", got.Status, domain.StatusActive)
	}
	if got.MutedUntil != nil {
		t.Fatal("Register() muted_until must be nil")
	}
	if got.ViolationCount != 0 {
		t.Fatalf("Register() violation count = %d, want 0", got.ViolationCount)
	}
	if !got.CreatedAt.Equal(wantTime) || got.CreatedAt.Location() != time.UTC || got.CreatedAt.Nanosecond() != 0 {
		t.Fatalf("Register() created_at = %v, want %v in UTC at second precision", got.CreatedAt, wantTime)
	}
	if !got.UpdatedAt.Equal(wantTime) || got.UpdatedAt.Location() != time.UTC || got.UpdatedAt.Nanosecond() != 0 {
		t.Fatalf("Register() updated_at = %v, want %v in UTC at second precision", got.UpdatedAt, wantTime)
	}
	if got.DeletedAt != nil {
		t.Fatal("Register() deleted_at must be nil")
	}
}

func assertUserViewContainsNoRegistrationSecrets(t *testing.T, got domain.UserView, forbidden ...string) {
	t.Helper()

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(UserView) error type = %T", err)
	}
	encodedText := string(encoded)
	if strings.Contains(strings.ToLower(encodedText), "password_hash") {
		t.Fatal("Register() user view JSON exposed a password-hash field")
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(encodedText, value) {
			t.Fatal("Register() user view JSON exposed registration secret material")
		}
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("json.Unmarshal(UserView) error type = %T", err)
	}
	wantKeys := []string{
		"id", "email", "display_name", "bio", "role", "status", "muted_until",
		"violation_count", "created_at", "updated_at", "deleted_at",
	}
	if len(payload) != len(wantKeys) {
		t.Fatalf("Register() user view JSON key count = %d, want %d", len(payload), len(wantKeys))
	}
	for _, key := range wantKeys {
		if _, ok := payload[key]; !ok {
			t.Fatalf("Register() user view JSON missing safe field %q", key)
		}
	}
}

func assertRegistrationValidationError(t *testing.T, err error, wantField ValidationField) {
	t.Helper()

	if err == nil {
		t.Fatal("Register() expected a validation error")
	}
	if !errors.Is(err, ErrValidationFailed) {
		t.Fatalf("Register() error type = %T, want ErrValidationFailed", err)
	}
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("Register() error type = %T, want ValidationError", err)
	}
	if validationErr.Field() != wantField {
		t.Fatalf("ValidationError.Field() = %q, want %q", validationErr.Field(), wantField)
	}
	if err.Error() != ErrValidationFailed.Error() {
		t.Fatal("ValidationError exposed unstable validator detail")
	}
	if errors.Is(err, ErrEmailAlreadyRegistered) || errors.Is(err, ErrInternal) {
		t.Fatal("Register() misclassified validation failure")
	}
}

func assertRegistrationInternalError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("Register() expected an internal error")
	}
	if !errors.Is(err, ErrInternal) {
		t.Fatalf("Register() error type = %T, want ErrInternal", err)
	}
	if err.Error() != ErrInternal.Error() {
		t.Fatal("Register() internal error text was not the stable safe message")
	}
	if errors.Is(err, ErrValidationFailed) || errors.Is(err, ErrEmailAlreadyRegistered) {
		t.Fatal("Register() mapped an internal failure to a public client error")
	}
}

func assertErrorTextOmitsPrivateValues(t *testing.T, err error, forbidden ...string) {
	t.Helper()

	if err == nil {
		t.Fatal("expected an error for private-value safety assertion")
	}
	message := strings.ToLower(err.Error())
	for _, value := range forbidden {
		if value != "" && strings.Contains(message, strings.ToLower(value)) {
			t.Fatal("service error text exposed private registration or dependency detail")
		}
	}
}

type secretRegistrationDependencyError struct{}

func (*secretRegistrationDependencyError) Error() string {
	return "secret driver SQL constraint hash detail"
}

func assertSafeInternalErrorPresentation(t *testing.T, err error, privateCause *secretRegistrationDependencyError) {
	t.Helper()

	if errors.Unwrap(err) != ErrInternal {
		t.Fatal("service internal error unwrap did not expose only ErrInternal")
	}
	if errors.Is(err, privateCause) {
		t.Fatal("service internal error exposed a private dependency cause through errors.Is")
	}
	var leaked *secretRegistrationDependencyError
	if errors.As(err, &leaked) {
		t.Fatal("service internal error exposed a private dependency cause through errors.As")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%q"} {
		assertSafeServiceErrorRendering(t, "fmt "+format, fmt.Sprintf(format, err))
	}

	encoded, marshalErr := json.Marshal(map[string]any{"error": err})
	if marshalErr != nil {
		t.Fatalf("json.Marshal(service error) error type = %T", marshalErr)
	}
	assertSafeServiceErrorRendering(t, "encoding/json", string(encoded))

	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Error("registration failed", slog.Any("error", err))
	assertSafeServiceErrorRendering(t, "slog JSON", logged.String())
}

func assertSafeServiceErrorRendering(t *testing.T, presentation, rendered string) {
	t.Helper()

	lowerRendered := strings.ToLower(rendered)
	for _, forbidden := range []string{"secret", "driver", "sql", "constraint", "hash detail"} {
		if strings.Contains(lowerRendered, forbidden) {
			t.Fatalf("%s representation leaked a private dependency detail", presentation)
		}
	}
}
