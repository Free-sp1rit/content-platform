package identity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
)

func TestFindUserUsesSecretFreeProjectionAndAlignedScanner(t *testing.T) {
	mutedUntil := time.Date(2026, time.September, 4, 12, 13, 14, 0, time.UTC)
	createdAt := time.Date(2026, time.August, 1, 13, 14, 15, 0, time.UTC)
	updatedAt := time.Date(2026, time.September, 1, 14, 15, 16, 0, time.UTC)
	deletedAt := time.Date(2026, time.September, 5, 15, 16, 17, 0, time.UTC)
	connection := &staticReadConnection{row: []driver.Value{
		int64(42), "safe@example.com", "Display 3", "Bio 4", "admin", "muted",
		mutedUntil, int64(8), createdAt, updatedAt, deletedAt,
	}}
	database := sql.OpenDB(staticReadConnector{connection: connection})
	defer database.Close()

	user, err := New(database).FindUser(context.Background(), 42)

	if err != nil {
		t.Fatalf("FindUser() error = %v", err)
	}
	want := domain.User{
		ID:             42,
		Email:          "safe@example.com",
		DisplayName:    "Display 3",
		Bio:            "Bio 4",
		Role:           domain.RoleAdmin,
		Status:         domain.StatusMuted,
		MutedUntil:     &mutedUntil,
		ViolationCount: 8,
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
		DeletedAt:      &deletedAt,
	}
	if !reflect.DeepEqual(user, want) {
		t.Fatalf("FindUser() = %#v, want %#v", user, want)
	}
	if user.PasswordHash != "" {
		t.Fatal("FindUser() populated PasswordHash")
	}
	query := normalizeSQLShape(connection.query)
	if !strings.Contains(query, "SELECT "+normalizeSQLShape(safeUserColumns)+" FROM users WHERE id = $1") {
		t.Fatalf("FindUser() query = %q, want safe user projection", query)
	}
	if strings.Contains(query, "password_hash") {
		t.Fatalf("FindUser() projected password_hash: %q", query)
	}
	if len(connection.arguments) != 1 || connection.arguments[0].Value != int64(42) {
		t.Fatalf("FindUser() arguments = %v, want user ID 42", connection.arguments)
	}
}
