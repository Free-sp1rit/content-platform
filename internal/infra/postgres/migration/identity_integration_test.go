//go:build integration

package migration_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/infra/postgres/migration"
)

func TestIdentityMigration(t *testing.T) {
	// Do not call t.Parallel: migration.Run serializes goose's process-global state and this test runs DDL.
	ctx, db, schema, directory := openIsolatedMigrationDatabase(t)
	assertCurrentSchema(t, ctx, db, schema)
	if err := migration.Run(ctx, db, directory, "up"); err != nil {
		t.Fatalf("run migrations up: %v", err)
	}
	assertMigrationVersion(t, ctx, db, 2)
	assertIdentityObjects(t, ctx, db, schema, true)

	userID := insertValidUser(t, ctx, db)
	insertValidSession(t, ctx, db, userID)
	insertValidAuditRows(t, ctx, db, userID)
	assertDuplicateEmailFails(t, ctx, db)
	assertInvalidUsersFail(t, ctx, db)
	assertInvalidSessionsFail(t, ctx, db, userID)
	assertInvalidAuditLogsFail(t, ctx, db, userID)

	if err := migration.Run(ctx, db, directory, "down-one"); err != nil {
		t.Fatalf("rollback identity migration: %v", err)
	}
	assertMigrationVersion(t, ctx, db, 1)
	assertIdentityObjects(t, ctx, db, schema, false)
	assertRelationExists(t, ctx, db, schema, "goose_db_version", true)

	if err := migration.Run(ctx, db, directory, "up"); err != nil {
		t.Fatalf("re-run migrations up: %v", err)
	}
	assertMigrationVersion(t, ctx, db, 2)
	assertIdentityObjects(t, ctx, db, schema, true)
}

func assertCurrentSchema(t *testing.T, ctx context.Context, db *sql.DB, want string) {
	t.Helper()
	var got string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&got); err != nil {
		t.Fatalf("read migration fixture schema: %v", err)
	}
	if got != want {
		t.Fatalf("migration fixture schema = %q, want %q", got, want)
	}
}

func assertMigrationVersion(t *testing.T, ctx context.Context, db *sql.DB, want int64) {
	t.Helper()
	var got int64
	if err := db.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version_id), 0)
		FROM goose_db_version
		WHERE is_applied`).Scan(&got); err != nil {
		t.Fatalf("get applied migration version: %v", err)
	}
	if got != want {
		t.Fatalf("applied migration version = %d, want %d", got, want)
	}
}

func assertIdentityObjects(t *testing.T, ctx context.Context, db *sql.DB, schema string, want bool) {
	t.Helper()
	for _, name := range []string{
		"users",
		"user_sessions",
		"audit_logs",
		"users_email_uidx",
		"user_sessions_user_created_idx",
		"user_sessions_active_user_idx",
		"audit_logs_target_created_idx",
	} {
		assertRelationExists(t, ctx, db, schema, name, want)
	}
	if want {
		assertIdentityIndexDefinitions(t, ctx, db, schema)
	}
}

func assertRelationExists(t *testing.T, ctx context.Context, db *sql.DB, schema, name string, want bool) {
	t.Helper()
	var got bool
	if err := db.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", schema+"."+name).Scan(&got); err != nil {
		t.Fatalf("check relation %s.%s: %v", schema, name, err)
	}
	if got != want {
		t.Fatalf("relation %s.%s exists = %t, want %t", schema, name, got, want)
	}
}

func assertIdentityIndexDefinitions(t *testing.T, ctx context.Context, db *sql.DB, schema string) {
	t.Helper()
	for _, testCase := range []struct {
		name      string
		table     string
		unique    bool
		columns   []string
		predicate string
	}{
		{
			name:    "users_email_uidx",
			table:   "users",
			unique:  true,
			columns: []string{"email"},
		},
		{
			name:    "user_sessions_user_created_idx",
			table:   "user_sessions",
			columns: []string{"user_id", "created_at desc"},
		},
		{
			name:      "user_sessions_active_user_idx",
			table:     "user_sessions",
			columns:   []string{"user_id", "id"},
			predicate: "revoked_at is null",
		},
		{
			name:    "audit_logs_target_created_idx",
			table:   "audit_logs",
			columns: []string{"target_type", "target_id", "created_at desc"},
		},
	} {
		t.Run(testCase.name+" definition", func(t *testing.T) {
			var indexOID int64
			var table, predicate string
			var unique bool
			var keyCount int
			err := db.QueryRowContext(ctx, `
				SELECT index_data.indexrelid::bigint,
				       table_relation.relname,
				       index_data.indisunique,
				       index_data.indnkeyatts,
				       COALESCE(pg_get_expr(index_data.indpred, index_data.indrelid), '')
				FROM pg_index AS index_data
				JOIN pg_class AS index_relation ON index_relation.oid = index_data.indexrelid
				JOIN pg_class AS table_relation ON table_relation.oid = index_data.indrelid
				JOIN pg_namespace AS namespace ON namespace.oid = index_relation.relnamespace
				WHERE namespace.nspname = $1 AND index_relation.relname = $2`,
				schema, testCase.name,
			).Scan(&indexOID, &table, &unique, &keyCount, &predicate)
			if err != nil {
				t.Fatalf("inspect index %s.%s: %v", schema, testCase.name, err)
			}
			if table != testCase.table {
				t.Fatalf("index %s table = %q, want %q", testCase.name, table, testCase.table)
			}
			if unique != testCase.unique {
				t.Fatalf("index %s unique = %t, want %t", testCase.name, unique, testCase.unique)
			}
			if keyCount != len(testCase.columns) {
				t.Fatalf("index %s key count = %d, want %d", testCase.name, keyCount, len(testCase.columns))
			}
			for position, expectedColumn := range testCase.columns {
				var columnDefinition string
				if err := db.QueryRowContext(ctx, "SELECT pg_get_indexdef($1::oid, $2, true)", indexOID, position+1).Scan(&columnDefinition); err != nil {
					t.Fatalf("inspect index %s column %d: %v", testCase.name, position+1, err)
				}
				if normalizedColumn := normalizeIndexSQL(columnDefinition); !strings.Contains(normalizedColumn, expectedColumn) {
					t.Fatalf("index %s column %d does not contain %q", testCase.name, position+1, expectedColumn)
				}
			}
			normalizedPredicate := normalizeIndexSQL(predicate)
			if testCase.predicate == "" {
				if normalizedPredicate != "" {
					t.Fatalf("index %s predicate = %q, want none", testCase.name, normalizedPredicate)
				}
			} else if !strings.Contains(normalizedPredicate, testCase.predicate) {
				t.Fatalf("index %s predicate does not contain %q", testCase.name, testCase.predicate)
			}
		})
	}
}

func normalizeIndexSQL(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, `"`, "")
	value = strings.Join(strings.Fields(value), " ")
	return strings.ReplaceAll(value, ", ", ",")
}

type userFixture struct {
	email          string
	passwordHash   string
	displayName    string
	bio            string
	role           string
	status         string
	mutedUntil     any
	violationCount int
	createdAt      time.Time
	updatedAt      time.Time
	deletedAt      any
}

func validUserFixture(t *testing.T) userFixture {
	t.Helper()
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	return userFixture{
		email:          "identity-" + randomMigrationTestSuffix(t) + "@example.test",
		passwordHash:   "password-hash",
		displayName:    "Identity User",
		bio:            "",
		role:           "user",
		status:         "active",
		mutedUntil:     nil,
		violationCount: 0,
		createdAt:      createdAt,
		updatedAt:      createdAt,
		deletedAt:      nil,
	}
}

func insertUser(ctx context.Context, db *sql.DB, fixture userFixture) (int64, error) {
	const query = `
		INSERT INTO users (
			email, password_hash, display_name, bio, role, status, muted_until,
			violation_count, created_at, updated_at, deleted_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id`
	var id int64
	err := db.QueryRowContext(ctx, query,
		fixture.email, fixture.passwordHash, fixture.displayName, fixture.bio, fixture.role,
		fixture.status, fixture.mutedUntil, fixture.violationCount, fixture.createdAt,
		fixture.updatedAt, fixture.deletedAt,
	).Scan(&id)
	return id, err
}

func insertValidUser(t *testing.T, ctx context.Context, db *sql.DB) int64 {
	t.Helper()
	id, err := insertUser(ctx, db, validUserFixture(t))
	if err != nil {
		t.Fatalf("insert valid user: %v", err)
	}
	return id
}

func insertValidSession(t *testing.T, ctx context.Context, db *sql.DB, userID int64) {
	t.Helper()
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	_, err := db.ExecContext(ctx, `
		INSERT INTO user_sessions (user_id, token_hash, expires_at, revoked_at, created_at)
		VALUES ($1, $2, $3, NULL, $4)`,
		userID, bytesOf(32), createdAt.Add(time.Hour), createdAt,
	)
	if err != nil {
		t.Fatalf("insert valid user session: %v", err)
	}
}

func insertValidAuditRows(t *testing.T, ctx context.Context, db *sql.DB, userID int64) {
	t.Helper()
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	for _, fixture := range []struct {
		actorType string
		actorID   any
		action    string
	}{
		{actorType: "system", actorID: nil, action: "user.mute_expired"},
		{actorType: "user", actorID: userID, action: "user.status_changed"},
		{actorType: "admin", actorID: userID, action: "user.status_changed"},
	} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, detail, created_at)
			VALUES ($1, $2, $3, 'user', $4, '{}'::jsonb, $5)`,
			fixture.actorType, fixture.actorID, fixture.action, userID, createdAt,
		)
		if err != nil {
			t.Fatalf("insert valid %s audit row: %v", fixture.actorType, err)
		}
	}
}

func assertDuplicateEmailFails(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	fixture := validUserFixture(t)
	if _, err := insertUser(ctx, db, fixture); err != nil {
		t.Fatalf("insert first duplicate-email fixture: %v", err)
	}
	if _, err := insertUser(ctx, db, fixture); err == nil {
		t.Fatal("expected constraint failure")
	}
}

func assertInvalidUsersFail(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for _, testCase := range []struct {
		name   string
		insert func(userFixture) error
	}{
		{
			name: "id is nonpositive",
			insert: func(fixture userFixture) error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO users (id, email, password_hash, display_name, bio, role, status, muted_until, violation_count, created_at, updated_at, deleted_at)
					VALUES (0, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
					fixture.email, fixture.passwordHash, fixture.displayName, fixture.bio, fixture.role,
					fixture.status, fixture.mutedUntil, fixture.violationCount, fixture.createdAt,
					fixture.updatedAt, fixture.deletedAt,
				)
				return err
			},
		},
		{
			name: "email is empty",
			insert: func(fixture userFixture) error {
				fixture.email = ""
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "email is not lowercase",
			insert: func(fixture userFixture) error {
				fixture.email = "Uppercase@example.test"
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "email has surrounding whitespace",
			insert: func(fixture userFixture) error {
				fixture.email = " user@example.test "
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "email exceeds 320 octets",
			insert: func(fixture userFixture) error {
				fixture.email = strings.Repeat("a", 321)
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "password hash is empty",
			insert: func(fixture userFixture) error {
				fixture.passwordHash = ""
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "display name is empty",
			insert: func(fixture userFixture) error {
				fixture.displayName = ""
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "display name exceeds 100 characters",
			insert: func(fixture userFixture) error {
				fixture.displayName = strings.Repeat("a", 101)
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "display name has surrounding whitespace",
			insert: func(fixture userFixture) error {
				fixture.displayName = " Identity User "
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "bio exceeds 1000 characters",
			insert: func(fixture userFixture) error {
				fixture.bio = strings.Repeat("a", 1001)
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "role is invalid",
			insert: func(fixture userFixture) error {
				fixture.role = "moderator"
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "status is invalid",
			insert: func(fixture userFixture) error {
				fixture.status = "unknown"
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "violation count is negative",
			insert: func(fixture userFixture) error {
				fixture.violationCount = -1
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "updated at is before created at",
			insert: func(fixture userFixture) error {
				fixture.updatedAt = fixture.createdAt.Add(-time.Second)
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "deleted at is before created at",
			insert: func(fixture userFixture) error {
				fixture.status = "deleted"
				fixture.deletedAt = fixture.createdAt.Add(-time.Second)
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "muted status has no muted until",
			insert: func(fixture userFixture) error {
				fixture.status = "muted"
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "non-muted status has muted until",
			insert: func(fixture userFixture) error {
				fixture.mutedUntil = fixture.createdAt.Add(time.Hour)
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "deleted status has no deleted at",
			insert: func(fixture userFixture) error {
				fixture.status = "deleted"
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
		{
			name: "non-deleted status has deleted at",
			insert: func(fixture userFixture) error {
				fixture.deletedAt = fixture.createdAt.Add(time.Hour)
				_, err := insertUser(ctx, db, fixture)
				return err
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.insert(validUserFixture(t)); err == nil {
				t.Fatal("expected constraint failure")
			}
		})
	}
}

func assertInvalidSessionsFail(t *testing.T, ctx context.Context, db *sql.DB, userID int64) {
	t.Helper()
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	for _, testCase := range []struct {
		name   string
		insert func() error
	}{
		{
			name: "id is nonpositive",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO user_sessions (id, user_id, token_hash, expires_at, revoked_at, created_at)
					VALUES (0, $1, $2, $3, NULL, $4)`, userID, bytesOf(32), createdAt.Add(time.Hour), createdAt)
				return err
			},
		},
		{
			name: "token hash is 31 bytes",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO user_sessions (user_id, token_hash, expires_at, revoked_at, created_at)
					VALUES ($1, $2, $3, NULL, $4)`, userID, bytesOf(31), createdAt.Add(time.Hour), createdAt)
				return err
			},
		},
		{
			name: "expires at equals created at",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO user_sessions (user_id, token_hash, expires_at, revoked_at, created_at)
					VALUES ($1, $2, $3, NULL, $4)`, userID, bytesOf(32), createdAt, createdAt)
				return err
			},
		},
		{
			name: "expires at is before created at",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO user_sessions (user_id, token_hash, expires_at, revoked_at, created_at)
					VALUES ($1, $2, $3, NULL, $4)`, userID, bytesOf(32), createdAt.Add(-time.Second), createdAt)
				return err
			},
		},
		{
			name: "revoked at is before created at",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO user_sessions (user_id, token_hash, expires_at, revoked_at, created_at)
					VALUES ($1, $2, $3, $4, $5)`, userID, bytesOf(32), createdAt.Add(time.Hour), createdAt.Add(-time.Second), createdAt)
				return err
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.insert(); err == nil {
				t.Fatal("expected constraint failure")
			}
		})
	}
}

func assertInvalidAuditLogsFail(t *testing.T, ctx context.Context, db *sql.DB, userID int64) {
	t.Helper()
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	for _, testCase := range []struct {
		name   string
		insert func() error
	}{
		{
			name: "id is nonpositive",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO audit_logs (id, actor_type, actor_id, action, target_type, target_id, detail, created_at)
					VALUES (0, 'system', NULL, 'action', 'user', $1, '{}'::jsonb, $2)`, userID, createdAt)
				return err
			},
		},
		{
			name: "actor type is invalid",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, detail, created_at)
					VALUES ('robot', $1, 'action', 'user', $1, '{}'::jsonb, $2)`, userID, createdAt)
				return err
			},
		},
		{
			name: "system actor has an actor id",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, detail, created_at)
					VALUES ('system', $1, 'action', 'user', $1, '{}'::jsonb, $2)`, userID, createdAt)
				return err
			},
		},
		{
			name: "user actor has no actor id",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, detail, created_at)
					VALUES ('user', NULL, 'action', 'user', $1, '{}'::jsonb, $2)`, userID, createdAt)
				return err
			},
		},
		{
			name: "admin actor has no actor id",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, detail, created_at)
					VALUES ('admin', NULL, 'action', 'user', $1, '{}'::jsonb, $2)`, userID, createdAt)
				return err
			},
		},
		{
			name: "detail is not an object",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, detail, created_at)
					VALUES ('system', NULL, 'action', 'user', $1, '[]'::jsonb, $2)`, userID, createdAt)
				return err
			},
		},
		{
			name: "action is empty",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, detail, created_at)
					VALUES ('system', NULL, '', 'user', $1, '{}'::jsonb, $2)`, userID, createdAt)
				return err
			},
		},
		{
			name: "target type is empty",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, detail, created_at)
					VALUES ('system', NULL, 'action', '', $1, '{}'::jsonb, $2)`, userID, createdAt)
				return err
			},
		},
		{
			name: "target id is nonpositive",
			insert: func() error {
				_, err := db.ExecContext(ctx, `
					INSERT INTO audit_logs (actor_type, actor_id, action, target_type, target_id, detail, created_at)
					VALUES ('system', NULL, 'action', 'user', 0, '{}'::jsonb, $1)`, createdAt)
				return err
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.insert(); err == nil {
				t.Fatal("expected constraint failure")
			}
		})
	}
}

func bytesOf(length int) []byte {
	return make([]byte, length)
}
