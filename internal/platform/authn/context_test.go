package authn

import (
	"context"
	"testing"
)

func TestPrincipalContextRoundTrip(t *testing.T) {
	want := Principal{UserID: 42, SessionID: 84}

	got, ok := FromContext(WithContext(context.Background(), want))

	if !ok {
		t.Fatal("FromContext() did not find principal")
	}
	if got != want {
		t.Fatalf("FromContext() = %+v, want %+v", got, want)
	}
}

func TestPrincipalContextRejectsAbsentOrWrongValues(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "absent", ctx: context.Background()},
		{name: "wrong type", ctx: context.WithValue(context.Background(), principalContextKey{}, "not-a-principal")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FromContext(tt.ctx)
			if ok {
				t.Fatalf("FromContext() = %+v, true; want zero principal, false", got)
			}
			if got != (Principal{}) {
				t.Fatalf("FromContext() principal = %+v, want zero value", got)
			}
		})
	}
}
