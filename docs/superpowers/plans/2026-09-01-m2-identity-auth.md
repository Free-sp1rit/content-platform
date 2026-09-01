# M2 Identity and Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete M2 Identity module: nine HTTP APIs, secure password and token handling, revocable sessions, profile lifecycle, user-status enforcement, mute expiry, transactional audit records, and PostgreSQL concurrency guarantees.

**Architecture:** Keep the repository business-module-first: `identity/handler -> identity/service -> identity/domain`, with JWT, bcrypt, clocks, random tokens, and PostgreSQL implementations under `internal/infra`. JWT middleware establishes only a `(user_id, session_id)` principal; every protected business operation rechecks current user/session state in PostgreSQL, and every write uses the documented `users -> user_sessions -> audit_logs` lock order.

**Tech Stack:** Go 1.26.4, `net/http`, `database/sql`, PostgreSQL/pgx v5.10.0, goose v3.27.1, `github.com/golang-jwt/jwt/v5` v5.3.1, `golang.org/x/crypto` v0.53.0, and `github.com/go-playground/validator/v10` v10.30.3.

---

## File map

| File | Responsibility |
| --- | --- |
| `internal/infra/config/{config,validate,log_value}.go` | Auth environment parsing, normalization, validation, and redaction |
| `internal/identity/domain/{user,session,validation}.go` | Identity entities, state capabilities, normalization, safe views |
| `internal/infra/clock/clock.go` | Production UTC clock |
| `internal/infra/password/bcrypt.go` | Bcrypt hashing, one-compare path support, startup dummy hash |
| `internal/infra/token/{access,refresh}.go` | Strict HS256 JWT and opaque `sid.secret` refresh tokens |
| `internal/platform/authn/{context,middleware}.go` | Principal context and JWT-only HTTP authentication |
| `migrations/00002_identity.sql` | `users`, `user_sessions`, and minimal `audit_logs` schema |
| `internal/identity/service/{service,ports,errors,auth,profile,status}.go` | Use-case contracts and transaction orchestration |
| `internal/infra/postgres/identity/{repository,user,session,audit}.go` | SQL reads, ordered locks, updates, session rotation/revocation, audit inserts |
| `internal/identity/handler/{handler,auth,profile,status,dto}.go` | Nine HTTP endpoints, JSON/path validation, DTO and error mapping |
| `internal/app/{app,routes}.go` | Composition root and route registration |
| `internal/testkit/postgres.go` | Build-tagged isolated PostgreSQL schema helper |
| `README.md`, `.env.example`, `migrations/README.md` | Operator, API, migration, and test documentation |

All production files receive focused `_test.go` counterparts in the same package. PostgreSQL behavior uses `//go:build integration` tests and only connects through `TEST_DATABASE_URL`.

## Task 1: Add fixed dependencies and Auth configuration

**Files:**

- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `internal/infra/config/config.go`
- Modify: `internal/infra/config/validate.go`
- Modify: `internal/infra/config/log_value.go`
- Modify: `internal/infra/config/config_test.go`
- Modify: `internal/infra/config/validate_test.go`
- Modify: `internal/infra/config/log_value_test.go`
- Modify: `cmd/migrate/main.go`
- Modify: `cmd/migrate/main_test.go`

- [ ] **Step 1: Write failing configuration tests**

Add `AUTH_*` keys to `configEnvironmentKeys`, set a 32-byte secret in existing successful `Load` tests, and add table-driven boundaries:

```go
func TestAuthConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*AuthConfig)
		wantErr string
	}{
		{name: "valid", mutate: func(*AuthConfig) {}},
		{name: "31 byte secret", mutate: func(c *AuthConfig) { c.JWTSecret = "1234567890123456789012345678901" }, wantErr: "AUTH_JWT_SECRET"},
		{name: "blank issuer", mutate: func(c *AuthConfig) { c.JWTIssuer = " " }, wantErr: "AUTH_JWT_ISSUER"},
		{name: "blank audience", mutate: func(c *AuthConfig) { c.JWTAudience = " " }, wantErr: "AUTH_JWT_AUDIENCE"},
		{name: "zero access TTL", mutate: func(c *AuthConfig) { c.AccessTokenTTL = 0 }, wantErr: "AUTH_ACCESS_TOKEN_TTL"},
		{name: "refresh not longer", mutate: func(c *AuthConfig) { c.RefreshTokenTTL = c.AccessTokenTTL }, wantErr: "AUTH_REFRESH_TOKEN_TTL"},
		{name: "cost below range", mutate: func(c *AuthConfig) { c.BcryptCost = 9 }, wantErr: "AUTH_BCRYPT_COST"},
		{name: "cost above range", mutate: func(c *AuthConfig) { c.BcryptCost = 16 }, wantErr: "AUTH_BCRYPT_COST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validAuthConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr == "" && err != nil { t.Fatalf("Validate() error = %v", err) }
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) { t.Fatalf("Validate() error = %v", err) }
		})
	}
}
```

Add a log assertion that neither the root config nor `AuthConfig` contains the configured secret and both contain `[REDACTED]`. Add a `cmd/migrate` test proving migration loading does not require `AUTH_JWT_SECRET`.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
go test -count=1 ./internal/infra/config ./cmd/migrate
```

Expected: FAIL because `AuthConfig`, auth parsing, redaction, and migration-scoped loading do not exist.

- [ ] **Step 3: Implement Auth configuration and scoped migration loading**

Add:

```go
type AuthConfig struct {
	JWTSecret      string        `env:"AUTH_JWT_SECRET"`
	JWTIssuer      string        `env:"AUTH_JWT_ISSUER" envDefault:"content-platform"`
	JWTAudience    string        `env:"AUTH_JWT_AUDIENCE" envDefault:"content-platform-api"`
	AccessTokenTTL time.Duration `env:"AUTH_ACCESS_TOKEN_TTL" envDefault:"15m"`
	RefreshTokenTTL time.Duration `env:"AUTH_REFRESH_TOKEN_TTL" envDefault:"720h"`
	BcryptCost     int           `env:"AUTH_BCRYPT_COST" envDefault:"12"`
}
```

Place `Auth AuthConfig` between Redis and Log in `Config`. Trim issuer/audience but preserve the secret byte-for-byte. Validate secret length `>=32`, positive TTLs, `RefreshTokenTTL > AccessTokenTTL`, and cost `10..15`. Add `LoadMigration()` returning only Environment/Database/Log configuration so migration commands do not need an unrelated JWT secret. Implement:

```go
func (c AuthConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("jwt_secret", redactedValue),
		slog.String("jwt_issuer", c.JWTIssuer),
		slog.String("jwt_audience", c.JWTAudience),
		slog.Duration("access_token_ttl", c.AccessTokenTTL),
		slog.Duration("refresh_token_ttl", c.RefreshTokenTTL),
		slog.Int("bcrypt_cost", c.BcryptCost),
	)
}
```

Pin the three direct dependencies at their specified versions.

- [ ] **Step 4: Format, tidy, and confirm GREEN**

Run:

```bash
gofmt -w internal/infra/config cmd/migrate
go mod tidy
go test -count=1 ./internal/infra/config ./cmd/migrate
go mod verify
```

Expected: all commands PASS; auth validation order is `Environment -> HTTP -> Database -> Redis -> Auth -> Log`.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/infra/config cmd/migrate
git commit -m "chore: add identity authentication config"
```

## Task 2: Add Identity domain model and validation

**Files:**

- Create: `internal/identity/domain/user.go`
- Create: `internal/identity/domain/session.go`
- Create: `internal/identity/domain/validation.go`
- Create: `internal/identity/domain/user_test.go`
- Create: `internal/identity/domain/session_test.go`

- [ ] **Step 1: Write failing domain boundary tests**

Cover email lower/trim and 320-byte limit, password `8..72` UTF-8 bytes, display name `1..100` runes after trim, bio `<=1000` runes, status capabilities, session validity, and deleted-public-view anonymization:

```go
func TestDeletedPublicViewIsAnonymous(t *testing.T) {
	u := User{ID: 7, DisplayName: "Admin", Bio: "secret", Role: RoleAdmin, Status: StatusDeleted}
	view := u.PublicView()
	if view.DisplayName != "Deleted User" || view.Bio != "" || view.Role != RoleUser || view.Status != StatusDeleted {
		t.Fatalf("PublicView() = %#v", view)
	}
}
```

- [ ] **Step 2: Run tests and confirm RED**

```bash
go test -count=1 ./internal/identity/domain
```

Expected: FAIL because the package and types do not exist.

- [ ] **Step 3: Implement pure domain types and rules**

Define `RoleUser`, `RoleAdmin`, six statuses, `User`, `UserSession`, `UserView`, `PublicUserView`, and validation functions:

```go
func NormalizeEmail(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func NormalizeDisplayName(value string) string { return strings.TrimSpace(value) }
func NormalizeTime(value time.Time) time.Time { return value.UTC().Truncate(time.Second) }

func (s Status) CanLogin() bool { return s != StatusBanned && s != StatusDeleted }
func (s Status) CanReadSelf() bool { return s != StatusBanned && s != StatusDeleted }
func (s Status) CanEditProfile() bool { return s == StatusPending || s == StatusActive || s == StatusMuted }
func (s Status) CanDeleteAccount() bool { return s == StatusPending || s == StatusActive || s == StatusMuted }
```

Use `validator.New().Var(email, "required,email")` only for email syntax; implement byte/rune bounds explicitly. Keep hash fields tagged `json:"-"` and expose responses through view structs only.

- [ ] **Step 4: Confirm GREEN**

```bash
gofmt -w internal/identity/domain
go test -count=1 ./internal/identity/domain
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/identity/domain
git commit -m "feat: add identity domain model"
```

## Task 3: Add bcrypt, JWT, refresh-token, clock, and principal adapters

**Files:**

- Create: `internal/infra/clock/clock.go`
- Create: `internal/infra/password/bcrypt.go`
- Create: `internal/infra/password/bcrypt_test.go`
- Create: `internal/infra/token/access.go`
- Create: `internal/infra/token/access_test.go`
- Create: `internal/infra/token/refresh.go`
- Create: `internal/infra/token/refresh_test.go`
- Create: `internal/platform/authn/context.go`
- Create: `internal/platform/authn/context_test.go`

- [ ] **Step 1: Write failing adapter tests**

Tests must cover bcrypt cost and 72-byte boundary; valid/dummy compare; HS256-only JWT; issuer/audience; required `sub/sid/iat/exp/jti`; canonical positive IDs; `exp > now`; `iat <= now+30s`; 4096-byte limit; `sid.secret` parsing; exactly 32 decoded secret bytes; SHA-256 and constant-time matching.

```go
func TestParsePositiveIDRejectsNonCanonicalValues(t *testing.T) {
	for _, raw := range []string{"", "0", "-1", "+1", " 1", "01", "9223372036854775808"} {
		if _, err := ParsePositiveID(raw); err == nil { t.Fatalf("ParsePositiveID(%q) succeeded", raw) }
	}
}
```

- [ ] **Step 2: Run tests and confirm RED**

```bash
go test -count=1 ./internal/infra/password ./internal/infra/token ./internal/platform/authn
```

Expected: FAIL because adapters are absent.

- [ ] **Step 3: Implement security adapters**

Use narrow value contracts:

```go
type Principal struct { UserID, SessionID int64 }
type AccessClaims struct { UserID, SessionID int64; IssuedAt, ExpiresAt time.Time; JWTID string }
type RefreshSecret struct { Encoded string; Hash [32]byte }
type ParsedRefreshToken struct { SessionID int64; Hash [32]byte }
```

`password.New(cost)` generates one legal dummy hash at startup. `token.AccessManager` signs only HS256 and manually validates exact expiration without global leeway. `token.RefreshCodec` uses `io.ReadFull(crypto/rand.Reader, 32)`, unpadded Base64URL, `sha256.Sum256`, and `subtle.ConstantTimeCompare`. `clock.System.Now()` returns UTC time. Principal context accessors return `(Principal, bool)` and use an unexported context key.

- [ ] **Step 4: Confirm GREEN and race safety**

```bash
gofmt -w internal/infra/clock internal/infra/password internal/infra/token internal/platform/authn
go test -count=1 ./internal/infra/password ./internal/infra/token ./internal/platform/authn
go test -race -count=1 ./internal/infra/password ./internal/infra/token ./internal/platform/authn
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/infra/clock internal/infra/password internal/infra/token internal/platform/authn
git commit -m "feat: add identity security adapters"
```

## Task 4: Add the Identity database schema

**Files:**

- Create: `migrations/00002_identity.sql`
- Create: `internal/infra/postgres/migration/identity_integration_test.go`
- Modify: `migrations/README.md`

- [ ] **Step 1: Write a failing migration/DDL integration test**

Create an isolated schema, run migrations, assert `users`, `user_sessions`, and `audit_logs` exist, then issue invalid inserts for email normalization, role/status, mute/deletion coherence, 31-byte token hash, invalid expiry, and non-object audit detail. Verify down-one removes the three M2 tables and a subsequent up restores them.

- [ ] **Step 2: Run the tagged test and confirm RED or explicit SKIP**

```bash
go test -count=1 -tags=integration ./internal/infra/postgres/migration -run TestIdentityMigration
```

Expected with `TEST_DATABASE_URL`: FAIL because migration `00002` is absent. Without it: explicit `SKIP`, which is not treated as PostgreSQL acceptance.

- [ ] **Step 3: Implement the migration**

Use the approved DDL shape:

```sql
-- +goose Up
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY CHECK (id > 0),
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    bio TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    status TEXT NOT NULL DEFAULT 'active',
    muted_until TIMESTAMPTZ NULL,
    violation_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ NULL,
    CHECK (email <> ''),
    CHECK (email = lower(btrim(email))),
    CHECK (octet_length(email) <= 320),
    CHECK (password_hash <> ''),
    CHECK (char_length(display_name) BETWEEN 1 AND 100),
    CHECK (display_name = btrim(display_name)),
    CHECK (char_length(bio) <= 1000),
    CHECK (role IN ('user', 'admin')),
    CHECK (status IN ('pending', 'active', 'muted', 'frozen', 'banned', 'deleted')),
    CHECK (violation_count >= 0),
    CHECK (updated_at >= created_at),
    CHECK (deleted_at IS NULL OR deleted_at >= created_at),
    CHECK ((status = 'muted' AND muted_until IS NOT NULL) OR (status <> 'muted' AND muted_until IS NULL)),
    CHECK ((status = 'deleted') = (deleted_at IS NOT NULL))
);
CREATE UNIQUE INDEX users_email_uidx ON users (email);
CREATE TABLE user_sessions (
    id BIGSERIAL PRIMARY KEY CHECK (id > 0),
    user_id BIGINT NOT NULL REFERENCES users(id),
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (octet_length(token_hash) = 32),
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX user_sessions_user_created_idx ON user_sessions (user_id, created_at DESC);
CREATE INDEX user_sessions_active_user_idx ON user_sessions (user_id, id) WHERE revoked_at IS NULL;
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY CHECK (id > 0),
    actor_type TEXT NOT NULL,
    actor_id BIGINT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id BIGINT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (action <> ''),
    CHECK (target_type <> ''),
    CHECK (target_id > 0),
    CHECK (jsonb_typeof(detail) = 'object'),
    CHECK (actor_type IN ('user', 'admin', 'system')),
    CHECK ((actor_type = 'system' AND actor_id IS NULL) OR (actor_type IN ('user', 'admin') AND actor_id IS NOT NULL))
);
CREATE INDEX audit_logs_target_created_idx ON audit_logs (target_type, target_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS users;
```

Copy every column, CHECK, index, actor rule, and time constraint from specification sections 8.1–8.3. Do not add database-generated current timestamps; the service supplies its injected clock.

- [ ] **Step 4: Confirm migration behavior**

```bash
go test -count=1 -tags=integration ./internal/infra/postgres/migration -run TestIdentityMigration
```

Expected with PostgreSQL: PASS. Without PostgreSQL: report explicit SKIP.

- [ ] **Step 5: Commit**

```bash
git add migrations/00002_identity.sql migrations/README.md internal/infra/postgres/migration/identity_integration_test.go
git commit -m "feat: add identity database schema"
```

## Task 5: Define service ports and PostgreSQL transaction primitives

**Files:**

- Create: `internal/identity/service/ports.go`
- Create: `internal/identity/service/service.go`
- Create: `internal/identity/service/errors.go`
- Create: `internal/infra/postgres/identity/repository.go`
- Create: `internal/infra/postgres/identity/user.go`
- Create: `internal/infra/postgres/identity/session.go`
- Create: `internal/infra/postgres/identity/audit.go`
- Create: `internal/infra/postgres/identity/repository_integration_test.go`

- [ ] **Step 1: Write failing transaction-port and repository tests**

Define compile-time interface assertions and tagged tests for unique-email mapping, user/session lookup, ascending locks, session insert/rotation, conditional logout, ordered bulk revocation, user update, conditional mute recovery, and audit insert rollback.

- [ ] **Step 2: Run focused tests and confirm RED**

```bash
go test -count=1 ./internal/identity/service ./internal/infra/postgres/identity
go test -count=1 -tags=integration ./internal/infra/postgres/identity
```

Expected: unit compile FAIL until ports exist; integration either FAIL against PostgreSQL or explicitly SKIP.

- [ ] **Step 3: Implement ports and repository**

Use callback transactions so SQL types do not escape infrastructure:

```go
type Repository interface {
	CreateUser(context.Context, CreateUserRecord) (domain.User, error)
	FindLoginCredential(context.Context, string) (LoginCredential, error)
	FindUser(context.Context, int64) (domain.User, error)
	FindSessionOwner(context.Context, int64) (int64, error)
	RevokeSession(context.Context, int64, int64, time.Time) error
	WithinTx(context.Context, func(context.Context, Tx) error) error
}

type Tx interface {
	LockUsers(context.Context, []int64) ([]LockedUser, error)
	LockSession(context.Context, int64) (domain.UserSession, error)
	LockActiveSessions(context.Context, int64) ([]domain.UserSession, error)
	CreateSession(context.Context, CreateSessionRecord) (domain.UserSession, error)
	RotateSessionToken(context.Context, int64, [32]byte) error
	RevokeLockedSessions(context.Context, []int64, time.Time) error
	UpdateUser(context.Context, UserMutation) (domain.User, error)
	InsertAudit(context.Context, AuditEntry) error
}
```

Sort and de-duplicate IDs inside repository methods. Map only PostgreSQL `23505` plus `users_email_uidx` to `ErrEmailExists`; preserve other errors as internal causes. Use the ordered CTE from specification section 14.2. Callback error and commit error must both leave no partial state.

- [ ] **Step 4: Confirm GREEN**

```bash
gofmt -w internal/identity/service internal/infra/postgres/identity
go test -count=1 ./internal/identity/service ./internal/infra/postgres/identity
go test -count=1 -tags=integration ./internal/infra/postgres/identity
```

Expected: default tests PASS; PostgreSQL tests PASS when configured or explicitly SKIP.

- [ ] **Step 5: Commit**

```bash
git add internal/identity/service internal/infra/postgres/identity
git commit -m "feat: add identity postgres repository"
```

## Task 6: Implement user registration

**Files:**

- Create: `internal/identity/service/register_test.go`
- Create: `internal/identity/service/auth.go`

- [ ] **Step 1: Write failing registration service tests**

Cover normalization, bcrypt input, fixed role/status/bio/count, safe view, hasher failure, repository failure, and `ErrEmailExists -> 409 email_already_registered`.

```go
got, err := svc.Register(ctx, RegisterInput{Email: " User@Example.com ", Password: "password", DisplayName: " Alice "})
if err != nil { t.Fatal(err) }
if got.Email != "user@example.com" || got.Role != domain.RoleUser || got.Status != domain.StatusActive { t.Fatalf("Register() = %#v", got) }
```

- [ ] **Step 2: Confirm RED**

```bash
go test -count=1 ./internal/identity/service -run TestRegister
```

Expected: FAIL because `Register` is absent.

- [ ] **Step 3: Implement registration**

Validate and normalize through domain functions, hash once, use `Clock.Now().UTC().Truncate(time.Second)`, call `CreateUser`, and convert only the repository email conflict to the public conflict error. Registration does not create a session or token.

- [ ] **Step 4: Confirm GREEN**

```bash
gofmt -w internal/identity/service
go test -count=1 ./internal/identity/service -run TestRegister
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/identity/service
git commit -m "feat: implement user registration"
```

## Task 7: Implement secure Login with a fixed bcrypt path

**Files:**

- Create: `internal/identity/service/login_test.go`
- Modify: `internal/identity/service/auth.go`
- Modify: `internal/identity/service/ports.go`

- [ ] **Step 1: Write failing login and rollback tests**

Table-test invalid email/password, missing user, bad password, banned/deleted, repository error, malformed hash, locked hash change, random failure, session insert failure, JWT failure, and commit failure. Every decoded service call asserts exactly one `PasswordHasher.Compare`. Assert success for pending/active/muted/frozen and `access_exp = min(now+TTL, session.expires_at)`.

- [ ] **Step 2: Confirm RED**

```bash
go test -count=1 ./internal/identity/service -run TestLogin
```

Expected: FAIL because login orchestration is absent.

- [ ] **Step 3: Implement the login transaction**

Follow this exact sequence:

```text
normalize and classify credentials
-> read real credential or choose dummy hash/candidate
-> exactly one bcrypt compare
-> begin transaction
-> lock user
-> recheck status, deleted_at, and unchanged password_hash
-> recover expired mute in the same transaction
-> generate refresh secret
-> insert session and receive id
-> generate CSPRNG jti and sign access JWT
-> commit
```

All credential/status failures return `invalid_credentials`. Repository read errors still execute dummy compare before returning `internal_error`. JWT/random failure rolls back session, mute recovery, and audit.

- [ ] **Step 4: Confirm GREEN and race safety**

```bash
gofmt -w internal/identity/service
go test -count=1 ./internal/identity/service -run TestLogin
go test -race -count=1 ./internal/identity/service
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/identity/service
git commit -m "feat: implement secure identity login"
```

## Task 8: Implement refresh-token rotation

**Files:**

- Create: `internal/identity/service/refresh_test.go`
- Modify: `internal/identity/service/auth.go`

- [ ] **Step 1: Write failing refresh tests**

Cover malformed token, missing owner, user/session invalidity, expired/revoked session, hash mismatch, expired absolute lifetime, mute recovery, new secret generation, JWT signing failure rollback, hash-update failure, commit failure, old secret reuse, and new access expiry bounded by the existing session.

- [ ] **Step 2: Confirm RED**

```bash
go test -count=1 ./internal/identity/service -run TestRefresh
```

Expected: FAIL because `Refresh` is absent.

- [ ] **Step 3: Implement one-time rotation**

Parse the token, pre-read only owner ID, then transactionally lock user before session, recheck all facts, perform constant-time hash comparison, restore mute, generate the new secret and signed access token, and only then update `token_hash`. Never update `expires_at`; map every caller-visible token/session/user failure to `401 invalid_refresh_token`.

- [ ] **Step 4: Confirm GREEN**

```bash
gofmt -w internal/identity/service
go test -count=1 ./internal/identity/service -run TestRefresh
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/identity/service
git commit -m "feat: implement refresh token rotation"
```

## Task 9: Add JWT middleware, strict authentication, and idempotent Logout

**Files:**

- Create: `internal/platform/authn/middleware.go`
- Create: `internal/platform/authn/middleware_test.go`
- Create: `internal/identity/service/authenticate_test.go`
- Modify: `internal/identity/service/auth.go`

- [ ] **Step 1: Write failing middleware/auth/logout tests**

Cover missing/malformed Bearer headers, oversized token, verifier error, principal context injection, strict session ownership/revocation/expiry, banned/deleted user, and repeated logout returning success even when the session is absent or revoked.

- [ ] **Step 2: Confirm RED**

```bash
go test -count=1 ./internal/platform/authn ./internal/identity/service -run 'Test(Middleware|Authenticate|Logout)'
```

Expected: FAIL.

- [ ] **Step 3: Implement two distinct authentication paths**

Middleware validates JWT only and writes `authn.Principal`. Strict service authentication reads the latest session/user and maps all server-side identity failures to `session_invalid`. Logout accepts the JWT principal directly and executes only:

```sql
UPDATE user_sessions
SET revoked_at = $3
WHERE id = $2 AND user_id = $1 AND revoked_at IS NULL;
```

Zero or one changed row is success; do not read/lock users and do not apply strict authentication to logout.

- [ ] **Step 4: Confirm GREEN**

```bash
gofmt -w internal/platform/authn internal/identity/service
go test -count=1 ./internal/platform/authn ./internal/identity/service
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/platform/authn internal/identity/service internal/infra/postgres/identity
git commit -m "feat: add identity authentication boundary"
```

## Task 10: Add profile queries and concurrent mute recovery

**Files:**

- Create: `internal/identity/service/profile.go`
- Create: `internal/identity/service/profile_test.go`
- Modify: `internal/infra/postgres/identity/user.go`
- Modify: `internal/infra/postgres/identity/audit.go`

- [ ] **Step 1: Write failing query and mute-recovery tests**

Cover `Me`, public user, missing user, deleted anonymization, response field boundaries, active mute, `muted_until == now`, conditional restore, system audit detail, audit failure rollback, and concurrent attempts producing one audit.

- [ ] **Step 2: Confirm RED**

```bash
go test -count=1 ./internal/identity/service -run 'Test(Me|PublicUser|Mute)'
```

Expected: FAIL.

- [ ] **Step 3: Implement reusable mute recovery**

Within an existing transaction, lock the user and conditionally change `muted -> active`, clear `muted_until`, update `updated_at`, then insert exactly one `user.mute_expired` system audit when one row changed. Read-only paths that discover expiry open a short transaction and return the post-recovery row. Include fixed old/new statuses, old/new mute times, and request ID in audit detail.

- [ ] **Step 4: Confirm GREEN**

```bash
gofmt -w internal/identity/service internal/infra/postgres/identity
go test -count=1 ./internal/identity/service
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/identity/service internal/infra/postgres/identity
git commit -m "feat: add identity profile queries"
```

## Task 11: Implement profile update and soft deletion

**Files:**

- Modify: `internal/identity/service/profile.go`
- Create: `internal/identity/service/profile_mutation_test.go`
- Modify: `internal/infra/postgres/identity/user.go`
- Modify: `internal/infra/postgres/identity/session.go`

- [ ] **Step 1: Write failing profile-mutation tests**

Cover absent/null fields, `{}` no-op, explicit empty display-name error, empty bio clear, same-value no-op, frozen rejection, mute recovery within the transaction, update failure, soft delete, all-session revocation, and rollback on revoke failure.

- [ ] **Step 2: Confirm RED**

```bash
go test -count=1 ./internal/identity/service -run 'Test(UpdateMe|DeleteMe)'
```

Expected: FAIL.

- [ ] **Step 3: Implement write transactions**

`UpdateMe` locks current user then current session, rechecks both, restores mute, rejects frozen, and updates only actual field changes. `DeleteMe` locks current user then all active sessions in ascending ID order, rechecks current session, rejects frozen, writes `status=deleted`, sets `deleted_at`, clears mute, and revokes all locked sessions at the same normalized time.

- [ ] **Step 4: Confirm GREEN**

```bash
gofmt -w internal/identity/service internal/infra/postgres/identity
go test -count=1 ./internal/identity/service
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/identity/service internal/infra/postgres/identity
git commit -m "feat: implement identity profile mutations"
```

## Task 12: Implement administrative status controls and audit

**Files:**

- Create: `internal/identity/service/status.go`
- Create: `internal/identity/service/status_test.go`
- Modify: `internal/infra/postgres/identity/user.go`
- Modify: `internal/infra/postgres/identity/session.go`
- Modify: `internal/infra/postgres/identity/audit.go`

- [ ] **Step 1: Write failing status-control tests**

Cover non-admin, frozen admin, invalid actor session, self target, other admin target, missing/deleted target, invalid status, mute-time validation before no-op, pending/banned to active, identical no-op, expired-mute recovery, banning with all-session revocation, audit detail, audit failure rollback, and sorted actor/target locks.

- [ ] **Step 2: Confirm RED**

```bash
go test -count=1 ./internal/identity/service -run TestChangeUserStatus
```

Expected: FAIL.

- [ ] **Step 3: Implement the ordered admin transaction**

Reject equal IDs before opening the transaction; otherwise sort actor/target IDs, lock both users, then actor session and necessary target sessions in ascending ID order. Recheck current actor role/status/session and target role/status/deletion. Validate `muted_until`, avoid row/audit writes for exact no-op, revoke target sessions when banning, and insert `user.status_changed` last. Map self/other-admin to `admin_target_forbidden`, non-admin to `admin_required`, frozen actor to `user_frozen`, and deleted target to `invalid_status_transition`.

- [ ] **Step 4: Confirm GREEN**

```bash
gofmt -w internal/identity/service internal/infra/postgres/identity
go test -count=1 ./internal/identity/service
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/identity/service internal/infra/postgres/identity
git commit -m "feat: add administrative user status controls"
```

## Task 13: Expose all nine HTTP APIs and assemble the module

**Files:**

- Create: `internal/identity/handler/handler.go`
- Create: `internal/identity/handler/dto.go`
- Create: `internal/identity/handler/auth.go`
- Create: `internal/identity/handler/profile.go`
- Create: `internal/identity/handler/status.go`
- Create: `internal/identity/handler/handler_test.go`
- Modify: `internal/platform/httpx/decode.go`
- Modify: `internal/platform/httpx/decode_test.go`
- Modify: `internal/app/routes.go`
- Modify: `internal/app/routes_test.go`
- Modify: `internal/app/app.go`
- Modify: `internal/app/assembly_test.go`
- Modify: `cmd/server/main_test.go`

- [ ] **Step 1: Write failing handler, route, and assembly tests**

Test all nine methods/paths and success statuses; JSON envelope/request ID; 64 KiB body; required `Content-Type: application/json`; malformed/unknown/multiple JSON as `invalid_request`; semantic fields as `validation_failed`; canonical path IDs; login field errors as `invalid_credentials`; JWT versus session error separation; `WWW-Authenticate: Bearer` on 401 responses; exact public/private DTO field whitelists; 405 `Allow`; and health/readiness regressions.

- [ ] **Step 2: Confirm RED**

```bash
go test -count=1 ./internal/identity/handler ./internal/app ./internal/platform/httpx ./cmd/server
```

Expected: FAIL because handlers and routes are absent.

- [ ] **Step 3: Implement DTOs, handlers, routes, and composition**

Register:

```go
mux.HandleFunc("POST /register", identity.Register)
mux.HandleFunc("POST /login", identity.Login)
mux.HandleFunc("POST /logout", authMiddleware(identity.Logout))
mux.HandleFunc("POST /token/refresh", identity.Refresh)
mux.HandleFunc("GET /me", authMiddleware(identity.Me))
mux.HandleFunc("PUT /me", authMiddleware(identity.UpdateMe))
mux.HandleFunc("DELETE /me", authMiddleware(identity.DeleteMe))
mux.HandleFunc("GET /users/{id}", identity.PublicUser)
mux.HandleFunc("PUT /admin/users/{id}/status", authMiddleware(identity.ChangeStatus))
```

Each known path also gets a method fallback and exact `Allow`. DTOs use pointers for nullable/absent patch fields and custom nullable RFC3339 decoding for `muted_until`. The composition root builds repository, bcrypt adapter, access/refresh managers, clock, service, middleware, and handler; Redis remains absent from identity correctness.

Map service failures to the approved public contract without exposing causes:

```go
var errorContract = map[string]struct {
	Kind apperror.Kind
	Code string
}{
	"invalid JSON/content type": {apperror.InvalidArgument, "invalid_request"},
	"invalid field/path value":  {apperror.InvalidArgument, "validation_failed"},
	"invalid access JWT":        {apperror.Unauthenticated, "invalid_access_token"},
	"invalid server session":    {apperror.Unauthenticated, "session_invalid"},
	"invalid login":             {apperror.Unauthenticated, "invalid_credentials"},
	"invalid refresh":           {apperror.Unauthenticated, "invalid_refresh_token"},
	"frozen user":               {apperror.PermissionDenied, "user_frozen"},
	"admin required":            {apperror.PermissionDenied, "admin_required"},
	"admin target forbidden":    {apperror.PermissionDenied, "admin_target_forbidden"},
	"user missing":              {apperror.NotFound, "user_not_found"},
	"email already registered":  {apperror.Conflict, "email_already_registered"},
	"invalid status transition": {apperror.Conflict, "invalid_status_transition"},
	"internal dependency":       {apperror.Internal, "internal_error"},
}
```

- [ ] **Step 4: Confirm GREEN and full default regression**

```bash
gofmt -w internal/identity/handler internal/platform/httpx internal/app cmd/server
go test -count=1 ./internal/identity/handler ./internal/app ./internal/platform/httpx ./cmd/server
go test -count=1 ./...
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/identity/handler internal/platform/httpx internal/app cmd/server
git commit -m "feat: expose identity authentication API"
```

## Task 14: Add real PostgreSQL atomicity and concurrency coverage

**Files:**

- Create: `internal/testkit/postgres.go`
- Create: `internal/infra/postgres/identity/concurrency_integration_test.go`
- Modify: `internal/infra/postgres/identity/repository_integration_test.go`
- Modify: `internal/infra/postgres/migration/identity_integration_test.go`
- Modify: `Makefile`

- [ ] **Step 1: Add isolated-schema fixtures and failing invariant tests**

Use unique schemas, migrations, unique fixture emails, channel barriers, and context deadlines. Cover two refreshes of one old token, refresh/logout, refresh/ban, refresh/delete, login/ban, login/delete, concurrent mute restore, two admins changing one user, actor deletion during admin action, and two admins targeting each other. Query final user/session/audit rows after each race.

- [ ] **Step 2: Run PostgreSQL tests and observe failures**

```bash
TEST_DATABASE_URL="$TEST_DATABASE_URL" go test -count=1 -tags=integration ./internal/infra/postgres/identity
```

Expected with PostgreSQL: at least one new test FAIL before missing synchronization/fixture support is completed. Without PostgreSQL: explicit SKIP, not acceptance.

- [ ] **Step 3: Complete repository synchronization and test helpers**

Adjust SQL only where a failing invariant demonstrates the need, preserving the global lock order. Add `test-integration-postgres`:

```make
test-integration-postgres:
	@test -n "$$TEST_DATABASE_URL" || (echo "TEST_DATABASE_URL is required" >&2; exit 1)
	go test -count=1 -tags=integration ./internal/infra/postgres/... ./internal/testkit/...
```

- [ ] **Step 4: Confirm tagged tests and race detector**

```bash
TEST_DATABASE_URL="$TEST_DATABASE_URL" go test -count=1 -tags=integration ./internal/infra/postgres/...
TEST_DATABASE_URL="$TEST_DATABASE_URL" go test -race -count=1 -tags=integration ./internal/infra/postgres/identity
```

Expected with PostgreSQL: PASS and no race reports. Without it: document SKIP and do not claim PostgreSQL acceptance.

- [ ] **Step 5: Commit**

```bash
git add internal/testkit internal/infra/postgres Makefile
git commit -m "test: cover identity postgres invariants"
```

## Task 15: Document M2 and run final verification

**Files:**

- Modify: `.env.example`
- Modify: `README.md`
- Modify: `migrations/README.md`
- Modify: `docs/superpowers/specs/2026-09-01-m2-identity-auth-design.md`
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Update operator and API documentation**

Document all six auth settings, CSPRNG secret guidance, nine routes, token/session lifetimes, one-time refresh rotation, logout special authentication, state matrix, mute recovery/audit, `00002_identity.sql`, parameterized admin promotion SQL, default versus PostgreSQL tests, and Redis exclusion from authentication correctness. Mark the design status implemented only after all implementation verification passes.

- [ ] **Step 2: Normalize dependencies and inspect drift**

```bash
go mod tidy
go mod verify
git diff -- go.mod go.sum
```

Expected: only reviewed direct/indirect dependency changes remain.

- [ ] **Step 3: Run the complete default verification gate**

```bash
test -z "$(gofmt -l $(rg --files -g '*.go'))"
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go build ./...
git diff --check
```

Expected: every command exits 0.

- [ ] **Step 4: Run and classify integration verification**

```bash
go test -count=1 -tags=integration ./...
```

Expected with configured PostgreSQL/Redis: PASS. If environment variables are absent, enumerate the explicit SKIP results and report that real external integration acceptance was not executed.

Recheck the protected user document:

```bash
sha256sum '内容平台——开发需求文档.md'
git status --short --branch
git log --oneline origin/main..HEAD
```

Expected document hash: `6e04a550cc63dcf24d215073a17adfdc5f4c7730d34ebfd48f7f61b3b9f1cb53`; the document remains untracked and absent from every M2 commit.

- [ ] **Step 5: Commit documentation**

```bash
git add .env.example README.md migrations/README.md docs/superpowers/specs/2026-09-01-m2-identity-auth-design.md go.mod go.sum
git commit -m "docs: document M2 identity and authentication"
```

After this task, invoke `superpowers:requesting-code-review`, resolve verified findings with `superpowers:receiving-code-review`, invoke `superpowers:verification-before-completion`, and finish the branch through `superpowers:finishing-a-development-branch` by pushing `feat/identity-auth` and creating a PR to `main`.
