package identity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
)

func TestLockSessionsQueryReturnsRowsFromLockingCTEWithoutOuterRescan(t *testing.T) {
	query := normalizeSQLShape(lockSessionsQuery("id IN ($1)"))
	columns := normalizeSQLShape(sessionColumns)

	if !strings.Contains(query, "WITH locked_sessions AS ( SELECT "+columns+" FROM user_sessions") {
		t.Fatalf("locking CTE does not project the complete session row")
	}
	if !strings.Contains(query, "FOR UPDATE ) SELECT "+columns+" FROM locked_sessions ORDER BY id") {
		t.Fatalf("final SELECT does not return the EvalPlanQual-checked row from the locking CTE")
	}
	if strings.Count(query, "FROM user_sessions") != 1 || strings.Contains(query, "JOIN user_sessions") {
		t.Fatalf("query performs an outer rescan of user_sessions after locking")
	}
}

func TestAuthenticationStateQueryUsesOneUnlockedJoinRead(t *testing.T) {
	query := normalizeSQLShape(authenticationStateQuery)

	for _, want := range []string{
		"SELECT s.id, s.user_id, s.expires_at, s.revoked_at, s.created_at",
		"u.id, u.email, u.display_name, u.bio, u.role, u.status, u.muted_until, u.violation_count, u.created_at, u.updated_at, u.deleted_at",
		"FROM user_sessions AS s JOIN users AS u ON u.id = s.user_id",
		"WHERE s.id = $1",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("authentication state query %q missing %q", query, want)
		}
	}
	if strings.Count(query, "SELECT") != 1 {
		t.Fatalf("authentication state query performs multiple SELECTs: %q", query)
	}
	if strings.Contains(query, "FOR UPDATE") {
		t.Fatalf("read-only authentication query takes a write lock: %q", query)
	}
	for _, secret := range []string{"token_hash", "password_hash"} {
		if strings.Contains(query, secret) {
			t.Fatalf("authentication state query projects secret column %q: %q", secret, query)
		}
	}
}

func TestFindAuthenticationStateDriverScanMatchesSafeProjection(t *testing.T) {
	sessionExpiresAt := time.Date(2026, time.September, 3, 9, 10, 11, 0, time.UTC)
	sessionRevokedAt := time.Date(2026, time.September, 2, 10, 11, 12, 0, time.UTC)
	sessionCreatedAt := time.Date(2026, time.September, 1, 11, 12, 13, 0, time.UTC)
	mutedUntil := time.Date(2026, time.September, 4, 12, 13, 14, 0, time.UTC)
	userCreatedAt := time.Date(2026, time.August, 1, 13, 14, 15, 0, time.UTC)
	userUpdatedAt := time.Date(2026, time.September, 1, 14, 15, 16, 0, time.UTC)
	userDeletedAt := time.Date(2026, time.September, 5, 15, 16, 17, 0, time.UTC)
	connection := &staticReadConnection{row: []driver.Value{
		int64(84), int64(42), sessionExpiresAt, sessionRevokedAt, sessionCreatedAt,
		int64(42), "safe@example.com", "Display 7", "Bio 8", "admin", "muted",
		mutedUntil, int64(9), userCreatedAt, userUpdatedAt, userDeletedAt,
	}}
	database := sql.OpenDB(staticReadConnector{connection: connection})
	defer database.Close()

	state, err := New(database).FindAuthenticationState(context.Background(), 84)

	if err != nil {
		t.Fatalf("FindAuthenticationState() error = %v", err)
	}
	want := identityservice.AuthenticationState{
		Session: identityservice.AuthenticationSession{
			ID:        84,
			UserID:    42,
			ExpiresAt: sessionExpiresAt,
			RevokedAt: &sessionRevokedAt,
			CreatedAt: sessionCreatedAt,
		},
		User: domain.User{
			ID:             42,
			Email:          "safe@example.com",
			DisplayName:    "Display 7",
			Bio:            "Bio 8",
			Role:           domain.RoleAdmin,
			Status:         domain.StatusMuted,
			MutedUntil:     &mutedUntil,
			ViolationCount: 9,
			CreatedAt:      userCreatedAt,
			UpdatedAt:      userUpdatedAt,
			DeletedAt:      &userDeletedAt,
		},
	}
	if !reflect.DeepEqual(state, want) {
		t.Fatalf("FindAuthenticationState() = %#v, want %#v", state, want)
	}
	if state.User.PasswordHash != "" {
		t.Fatal("FindAuthenticationState() populated PasswordHash")
	}
	if got := normalizeSQLShape(connection.query); got != normalizeSQLShape(authenticationStateQuery) {
		t.Fatalf("FindAuthenticationState() query = %q, want authenticationStateQuery", got)
	}
	if len(connection.arguments) != 1 || connection.arguments[0].Value != int64(84) {
		t.Fatalf("FindAuthenticationState() arguments = %v, want session ID 84", connection.arguments)
	}
}

func TestFindAuthenticationStateClassifiesDriverReadFailures(t *testing.T) {
	t.Run("no rows", func(t *testing.T) {
		database := sql.OpenDB(staticReadConnector{connection: &staticReadConnection{}})
		defer database.Close()

		state, err := New(database).FindAuthenticationState(context.Background(), 84)

		if state != (identityservice.AuthenticationState{}) || err != identityservice.ErrNotFound {
			t.Fatalf("FindAuthenticationState(no rows) = %#v/%T, want zero/exact ErrNotFound", state, err)
		}
	})

	t.Run("scan error", func(t *testing.T) {
		connection := &staticReadConnection{row: []driver.Value{
			"not-a-session-id", int64(42), time.Now(), nil, time.Now(),
			int64(42), "safe@example.com", "Display", "Bio", "user", "active",
			nil, int64(0), time.Now(), time.Now(), nil,
		}}
		database := sql.OpenDB(staticReadConnector{connection: connection})
		defer database.Close()

		state, err := New(database).FindAuthenticationState(context.Background(), 84)

		if state != (identityservice.AuthenticationState{}) || !errors.Is(err, identityservice.ErrInternal) {
			t.Fatalf("FindAuthenticationState(scan error) = %#v/%T, want zero/ErrInternal", state, err)
		}
		if strings.Contains(strings.ToLower(err.Error()), "session") || strings.Contains(strings.ToLower(err.Error()), "not-a-session-id") {
			t.Fatal("FindAuthenticationState() leaked scan details")
		}
	})

	for _, contextErr := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(contextErr.Error(), func(t *testing.T) {
			connection := &staticReadConnection{queryErr: contextErr}
			database := sql.OpenDB(staticReadConnector{connection: connection})
			defer database.Close()

			state, err := New(database).FindAuthenticationState(context.Background(), 84)

			if state != (identityservice.AuthenticationState{}) || !errors.Is(err, identityservice.ErrInternal) || !errors.Is(err, contextErr) {
				t.Fatalf("FindAuthenticationState(%v) = %#v/%T, want zero/ErrInternal with context classification", contextErr, state, err)
			}
		})
	}
}

func TestRevokeSessionTreatsZeroOrOneAffectedRowsAsSuccess(t *testing.T) {
	for _, affectedRows := range []int64{0, 1} {
		t.Run(string(rune('0'+affectedRows))+" rows", func(t *testing.T) {
			connection := &revokeSessionConnection{affectedRows: affectedRows}
			database := sql.OpenDB(revokeSessionConnector{connection: connection})
			defer database.Close()
			repository := New(database)
			revokedAt := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)

			err := repository.RevokeSession(context.Background(), identityservice.RevokeSessionRequest{
				UserID:    42,
				SessionID: 84,
				RevokedAt: revokedAt,
			})

			if err != nil {
				t.Fatalf("RevokeSession(%d affected rows) error = %v", affectedRows, err)
			}
			query := normalizeSQLShape(connection.query)
			for _, want := range []string{
				"UPDATE user_sessions SET revoked_at = $3",
				"WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
			} {
				if !strings.Contains(query, want) {
					t.Fatalf("RevokeSession() query %q missing %q", query, want)
				}
			}
			if len(connection.arguments) != 3 {
				t.Fatalf("RevokeSession() arguments = %v", connection.arguments)
			}
			if connection.arguments[0].Value != int64(84) || connection.arguments[1].Value != int64(42) || connection.arguments[2].Value != revokedAt {
				t.Fatalf("RevokeSession() arguments = %v", connection.arguments)
			}
		})
	}
}

func TestRevokeLockedSessionsRequiresEveryPreviouslyLockedRowToBeUpdated(t *testing.T) {
	connection := &revokeSessionConnection{affectedRows: 0}
	database := sql.OpenDB(revokeSessionConnector{connection: connection})
	defer database.Close()

	err := New(database).WithinTx(context.Background(), func(ctx context.Context, tx identityservice.Tx) error {
		return tx.RevokeLockedSessions(ctx, []int64{84}, time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC))
	})

	if !errors.Is(err, identityservice.ErrInternal) {
		t.Fatalf("RevokeLockedSessions(0 affected rows) error = %v, want ErrInternal", err)
	}
}

func normalizeSQLShape(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

type revokeSessionConnector struct {
	connection *revokeSessionConnection
}

type staticReadConnector struct {
	connection *staticReadConnection
}

func (c staticReadConnector) Connect(context.Context) (driver.Conn, error) {
	return c.connection, nil
}

func (staticReadConnector) Driver() driver.Driver {
	return staticReadDriver{}
}

type staticReadDriver struct{}

func (staticReadDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("static read test driver uses Connector")
}

type staticReadConnection struct {
	row       []driver.Value
	queryErr  error
	query     string
	arguments []driver.NamedValue
}

func (*staticReadConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not supported")
}

func (*staticReadConnection) Close() error {
	return nil
}

func (*staticReadConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not supported")
}

func (c *staticReadConnection) QueryContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	c.query = query
	c.arguments = append([]driver.NamedValue(nil), arguments...)
	if c.queryErr != nil {
		return nil, c.queryErr
	}
	return &staticReadRows{row: append([]driver.Value(nil), c.row...)}, nil
}

type staticReadRows struct {
	row  []driver.Value
	done bool
}

func (r *staticReadRows) Columns() []string {
	columns := make([]string, len(r.row))
	for index := range columns {
		columns[index] = fmt.Sprintf("column_%02d", index+1)
	}
	return columns
}

func (*staticReadRows) Close() error {
	return nil
}

func (r *staticReadRows) Next(destination []driver.Value) error {
	if r.done || len(r.row) == 0 {
		return io.EOF
	}
	r.done = true
	copy(destination, r.row)
	return nil
}

func (c revokeSessionConnector) Connect(context.Context) (driver.Conn, error) {
	return c.connection, nil
}

func (revokeSessionConnector) Driver() driver.Driver {
	return revokeSessionDriver{}
}

type revokeSessionDriver struct{}

func (revokeSessionDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("revoke session test driver uses Connector")
}

type revokeSessionConnection struct {
	affectedRows int64
	query        string
	arguments    []driver.NamedValue
}

func (*revokeSessionConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not supported")
}

func (*revokeSessionConnection) Close() error {
	return nil
}

func (*revokeSessionConnection) Begin() (driver.Tx, error) {
	return revokeSessionDriverTx{}, nil
}

func (c *revokeSessionConnection) ExecContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	c.query = query
	c.arguments = append([]driver.NamedValue(nil), arguments...)
	return driver.RowsAffected(c.affectedRows), nil
}

type revokeSessionDriverTx struct{}

func (revokeSessionDriverTx) Commit() error   { return nil }
func (revokeSessionDriverTx) Rollback() error { return nil }
