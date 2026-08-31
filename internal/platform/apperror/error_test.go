package apperror

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorWrapsCauseAndDetails(t *testing.T) {
	cause := errors.New("driver detail")
	err := Wrap(Conflict, "version_conflict", "resource version conflict", cause).
		WithDetails(map[string]any{"expected": 2})

	if !errors.Is(err, cause) {
		t.Fatal("wrapped cause is not discoverable")
	}
	got, ok := From(err)
	if !ok || got.Kind != Conflict || got.Code != "version_conflict" {
		t.Fatalf("From() = %#v, %v", got, ok)
	}
	if strings.Contains(err.Error(), "driver detail") {
		t.Fatalf("Error() leaks private cause: %q", err.Error())
	}
	details, ok := got.Details.(map[string]any)
	if !ok || details["expected"] != 2 {
		t.Fatalf("unexpected details: %#v", got.Details)
	}
}

func TestFromFindsWrappedApplicationError(t *testing.T) {
	want := New(NotFound, "article_not_found", "article not found")
	got, ok := From(errors.Join(errors.New("outer"), want))
	if !ok || got != want {
		t.Fatalf("From() = %#v, %v", got, ok)
	}
}

func TestFromRejectsOrdinaryError(t *testing.T) {
	if got, ok := From(errors.New("ordinary")); ok || got != nil {
		t.Fatalf("From() = %#v, %v", got, ok)
	}
}
