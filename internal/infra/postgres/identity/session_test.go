package identity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

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
		"SELECT s.id, s.user_id, s.token_hash, s.expires_at, s.revoked_at, s.created_at",
		"u.id, u.email, u.password_hash, u.display_name, u.bio, u.role, u.status, u.muted_until, u.violation_count, u.created_at, u.updated_at, u.deleted_at",
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

func normalizeSQLShape(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

type revokeSessionConnector struct {
	connection *revokeSessionConnection
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
	return nil, errors.New("transactions are not supported")
}

func (c *revokeSessionConnection) ExecContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	c.query = query
	c.arguments = append([]driver.NamedValue(nil), arguments...)
	return driver.RowsAffected(c.affectedRows), nil
}
