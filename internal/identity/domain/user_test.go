package domain

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "trim and lowercase", input: " User@Example.COM ", want: "user@example.com"},
		{name: "unicode lowercase", input: " ÜSER@Example.COM ", want: "üser@example.com"},
		{name: "already normalized", input: "user@example.com", want: "user@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeEmail(tt.input); got != tt.want {
				t.Fatalf("NormalizeEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	exact320Bytes := strings.Repeat("界", 102) + "ab@example.com"
	over320Bytes := strings.Repeat("界", 102) + "abc@example.com"
	if got := len(exact320Bytes); got != 320 {
		t.Fatalf("exact-boundary fixture length = %d, want 320 bytes", got)
	}
	if got := len(over320Bytes); got != 321 {
		t.Fatalf("over-boundary fixture length = %d, want 321 bytes", got)
	}
	if got := utf8.RuneCountInString(exact320Bytes); got >= 320 {
		t.Fatalf("multibyte fixture rune count = %d, want fewer than 320", got)
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "required", input: "", wantErr: true},
		{name: "invalid syntax", input: "not-an-email", wantErr: true},
		{name: "missing top-level domain", input: "user@example", wantErr: true},
		{name: "valid normalized email", input: NormalizeEmail(" User@Example.COM ")},
		{name: "exactly 320 UTF-8 bytes", input: exact320Bytes},
		{name: "321 UTF-8 bytes", input: over320Bytes, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.input)
			if tt.wantErr && err == nil {
				t.Fatal("ValidateEmail() expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateEmail() error = %v", err)
			}
		})
	}
}

func TestValidateRegistrationPasswordUsesUTF8ByteLength(t *testing.T) {
	exact8Multibyte := "界界ab"
	if got := len(exact8Multibyte); got != 8 {
		t.Fatalf("8-byte fixture length = %d", got)
	}

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "7 bytes", value: strings.Repeat("a", 7), wantErr: true},
		{name: "8 bytes", value: strings.Repeat("a", 8)},
		{name: "8 multibyte bytes", value: exact8Multibyte},
		{name: "72 bytes", value: strings.Repeat("a", 72)},
		{name: "72 multibyte bytes", value: strings.Repeat("界", 24)},
		{name: "73 bytes", value: strings.Repeat("a", 73), wantErr: true},
		{name: "73 multibyte bytes", value: strings.Repeat("界", 24) + "a", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRegistrationPassword(tt.value)
			if tt.wantErr && err == nil {
				t.Fatal("ValidateRegistrationPassword() expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateRegistrationPassword() error = %v", err)
			}
		})
	}
}

func TestNormalizeAndValidateDisplayName(t *testing.T) {
	if got := NormalizeDisplayName("  Alice  "); got != "Alice" {
		t.Fatalf("NormalizeDisplayName() = %q, want %q", got, "Alice")
	}

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "zero runes after trim", value: " \t\n ", wantErr: true},
		{name: "one rune", value: "界"},
		{name: "one rune after trim", value: "  界  "},
		{name: "100 runes", value: strings.Repeat("界", 100)},
		{name: "101 runes", value: strings.Repeat("界", 101), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := NormalizeDisplayName(tt.value)
			err := ValidateDisplayName(normalized)
			if tt.wantErr && err == nil {
				t.Fatal("ValidateDisplayName() expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateDisplayName() error = %v", err)
			}
		})
	}
}

func TestValidateBioUsesUnicodeRuneLength(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "empty", value: ""},
		{name: "whitespace is preserved", value: "  bio  "},
		{name: "1000 runes", value: strings.Repeat("界", 1000)},
		{name: "1001 runes", value: strings.Repeat("界", 1001), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBio(tt.value)
			if tt.wantErr && err == nil {
				t.Fatal("ValidateBio() expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateBio() error = %v", err)
			}
		})
	}
}

func TestStatusCapabilities(t *testing.T) {
	tests := []struct {
		name          string
		status        Status
		login         bool
		readSelf      bool
		editProfile   bool
		deleteAccount bool
		contentWrites bool
	}{
		{name: "pending", status: StatusPending, login: true, readSelf: true, editProfile: true, deleteAccount: true},
		{name: "active", status: StatusActive, login: true, readSelf: true, editProfile: true, deleteAccount: true, contentWrites: true},
		{name: "muted", status: StatusMuted, login: true, readSelf: true, editProfile: true, deleteAccount: true},
		{name: "frozen", status: StatusFrozen, login: true, readSelf: true},
		{name: "banned", status: StatusBanned},
		{name: "deleted", status: StatusDeleted},
		{name: "unknown defaults denied", status: Status("unknown")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks := map[string]struct {
				got  bool
				want bool
			}{
				"CanLogin":         {got: tt.status.CanLogin(), want: tt.login},
				"CanReadSelf":      {got: tt.status.CanReadSelf(), want: tt.readSelf},
				"CanEditProfile":   {got: tt.status.CanEditProfile(), want: tt.editProfile},
				"CanDeleteAccount": {got: tt.status.CanDeleteAccount(), want: tt.deleteAccount},
				"CanWriteArticle":  {got: tt.status.CanWriteArticle(), want: tt.contentWrites},
				"CanWriteComment":  {got: tt.status.CanWriteComment(), want: tt.contentWrites},
				"CanInteract":      {got: tt.status.CanInteract(), want: tt.contentWrites},
				"CanRepost":        {got: tt.status.CanRepost(), want: tt.contentWrites},
				"CanSendMessage":   {got: tt.status.CanSendMessage(), want: tt.contentWrites},
			}
			for method, check := range checks {
				if check.got != check.want {
					t.Errorf("%s() = %t, want %t", method, check.got, check.want)
				}
			}
		})
	}
}

func TestNormalizeTimeUsesUTCSecondPrecision(t *testing.T) {
	location := time.FixedZone("UTC+08", 8*60*60)
	input := time.Date(2026, time.September, 1, 19, 20, 21, 987654321, location)
	want := time.Date(2026, time.September, 1, 11, 20, 21, 0, time.UTC)

	if got := NormalizeTime(input); !got.Equal(want) || got.Location() != time.UTC || got.Nanosecond() != 0 {
		t.Fatalf("NormalizeTime() = %v, want %v in UTC at second precision", got, want)
	}
}

func TestUserViewIncludesAllSafeSelfFields(t *testing.T) {
	location := time.FixedZone("UTC+08", 8*60*60)
	mutedUntil := time.Date(2026, time.September, 2, 12, 30, 45, 999, location)
	deletedAt := time.Date(2026, time.September, 3, 13, 40, 55, 888, location)
	user := User{
		ID:             7,
		Email:          "admin@example.com",
		PasswordHash:   "password-hash-do-not-expose",
		DisplayName:    "Admin",
		Bio:            "profile",
		Role:           RoleAdmin,
		Status:         StatusMuted,
		MutedUntil:     &mutedUntil,
		ViolationCount: 3,
		CreatedAt:      time.Date(2026, time.September, 1, 10, 1, 2, 333, location),
		UpdatedAt:      time.Date(2026, time.September, 1, 11, 2, 3, 444, location),
		DeletedAt:      &deletedAt,
	}

	wantMutedUntil := NormalizeTime(mutedUntil)
	wantDeletedAt := NormalizeTime(deletedAt)
	want := UserView{
		ID:             7,
		Email:          "admin@example.com",
		DisplayName:    "Admin",
		Bio:            "profile",
		Role:           RoleAdmin,
		Status:         StatusMuted,
		MutedUntil:     &wantMutedUntil,
		ViolationCount: 3,
		CreatedAt:      NormalizeTime(user.CreatedAt),
		UpdatedAt:      NormalizeTime(user.UpdatedAt),
		DeletedAt:      &wantDeletedAt,
	}

	if got := user.View(); !reflect.DeepEqual(got, want) {
		t.Fatalf("View() = %#v, want %#v", got, want)
	}
	assertJSONKeys(t, user.View(), []string{
		"id", "email", "display_name", "bio", "role", "status", "muted_until",
		"violation_count", "created_at", "updated_at", "deleted_at",
	})
}

func TestUserViewSerializesOptionalTimesAsNull(t *testing.T) {
	encoded, err := json.Marshal(User{}.View())
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload["muted_until"] != nil {
		t.Fatalf("muted_until = %#v, want null", payload["muted_until"])
	}
	if payload["deleted_at"] != nil {
		t.Fatalf("deleted_at = %#v, want null", payload["deleted_at"])
	}
}

func TestUserJSONNeverExposesPasswordHash(t *testing.T) {
	encoded, err := json.Marshal(User{PasswordHash: "password-hash-do-not-expose"})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), "PasswordHash") || strings.Contains(string(encoded), "password_hash") || strings.Contains(string(encoded), "password-hash-do-not-expose") {
		t.Fatal("User JSON exposed PasswordHash")
	}
}

func TestPublicUserViewUsesStrictWhitelist(t *testing.T) {
	createdAt := time.Date(2026, time.September, 1, 11, 20, 21, 987654321, time.FixedZone("UTC+08", 8*60*60))
	user := User{
		ID:             8,
		Email:          "user@example.com",
		PasswordHash:   "password-hash-do-not-expose",
		DisplayName:    "Alice",
		Bio:            "public bio",
		Role:           RoleUser,
		Status:         StatusActive,
		ViolationCount: 9,
		CreatedAt:      createdAt,
		UpdatedAt:      createdAt.Add(time.Hour),
	}

	want := PublicUserView{
		ID:          8,
		DisplayName: "Alice",
		Bio:         "public bio",
		Role:        RoleUser,
		Status:      StatusActive,
		CreatedAt:   NormalizeTime(createdAt),
	}
	if got := user.PublicView(); !reflect.DeepEqual(got, want) {
		t.Fatalf("PublicView() = %#v, want %#v", got, want)
	}
	assertJSONKeys(t, user.PublicView(), []string{"id", "display_name", "bio", "role", "status", "created_at"})
}

func TestDeletedPublicViewIsAnonymous(t *testing.T) {
	createdAt := time.Date(2026, time.September, 1, 11, 20, 21, 987654321, time.FixedZone("UTC+08", 8*60*60))
	user := User{
		ID:           7,
		Email:        "admin@example.com",
		PasswordHash: "password-hash-do-not-expose",
		DisplayName:  "Admin",
		Bio:          "secret",
		Role:         RoleAdmin,
		Status:       StatusDeleted,
		CreatedAt:    createdAt,
	}

	want := PublicUserView{
		ID:          7,
		DisplayName: "Deleted User",
		Bio:         "",
		Role:        RoleUser,
		Status:      StatusDeleted,
		CreatedAt:   NormalizeTime(createdAt),
	}
	if got := user.PublicView(); !reflect.DeepEqual(got, want) {
		t.Fatalf("PublicView() = %#v, want %#v", got, want)
	}
}

func assertJSONKeys(t *testing.T, value any, expected []string) {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(payload) != len(expected) {
		t.Fatalf("JSON keys = %v, want exactly %v", mapKeys(payload), expected)
	}
	for _, key := range expected {
		if _, ok := payload[key]; !ok {
			t.Fatalf("JSON missing key %q; got %v", key, mapKeys(payload))
		}
	}
}

func mapKeys(values map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
