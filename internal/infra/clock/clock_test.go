package clock

import (
	"testing"
	"time"
)

func TestSystemNowReturnsCurrentUTCTime(t *testing.T) {
	before := time.Now().UTC()
	got := (System{}).Now()
	after := time.Now().UTC()

	if got.Location() != time.UTC {
		t.Fatalf("Now() location = %v, want UTC", got.Location())
	}
	if got.Before(before) || got.After(after) {
		t.Fatalf("Now() = %v, want time between %v and %v", got, before, after)
	}
}
