package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLivenessDoesNotCheckDependencies(t *testing.T) {
	health := New(panicChecker{}, panicChecker{}, time.Second, time.Second)
	if got := health.Liveness(context.Background()); got.Status != "ok" {
		t.Fatalf("Liveness() = %#v", got)
	}
}

func TestReadinessMatrix(t *testing.T) {
	tests := []struct {
		name       string
		postgres   error
		redis      error
		wantStatus Status
		wantPG     DependencyState
		wantRedis  DependencyState
	}{
		{name: "ready", wantStatus: Ready, wantPG: Up, wantRedis: Up},
		{name: "Redis degraded", redis: errors.New("down"), wantStatus: Degraded, wantPG: Up, wantRedis: Down},
		{name: "PostgreSQL unavailable", postgres: errors.New("down"), wantStatus: NotReady, wantPG: Down, wantRedis: Up},
		{name: "both unavailable", postgres: errors.New("down"), redis: errors.New("down"), wantStatus: NotReady, wantPG: Down, wantRedis: Down},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			health := New(fakeChecker{err: tt.postgres}, fakeChecker{err: tt.redis}, time.Second, time.Second)

			got := health.Readiness(context.Background())

			if got.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			if got.Checks["postgres"] != tt.wantPG || got.Checks["redis"] != tt.wantRedis {
				t.Fatalf("checks = %#v", got.Checks)
			}
		})
	}
}

func TestReadinessHonorsDependencyTimeout(t *testing.T) {
	health := New(blockingChecker{}, fakeChecker{}, 10*time.Millisecond, time.Second)
	started := time.Now()

	got := health.Readiness(context.Background())

	if got.Status != NotReady || got.Checks["postgres"] != Down {
		t.Fatalf("timeout result = %#v", got)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("readiness timeout took %s", elapsed)
	}
}

func TestReadinessChecksDependenciesConcurrently(t *testing.T) {
	health := New(delayChecker{delay: 60 * time.Millisecond}, delayChecker{delay: 60 * time.Millisecond}, time.Second, time.Second)
	started := time.Now()

	got := health.Readiness(context.Background())

	if got.Status != Ready {
		t.Fatalf("Readiness() = %#v", got)
	}
	if elapsed := time.Since(started); elapsed > 110*time.Millisecond {
		t.Fatalf("dependency checks were not concurrent: %s", elapsed)
	}
}

type fakeChecker struct {
	err error
}

func (c fakeChecker) Ping(context.Context) error {
	return c.err
}

type blockingChecker struct{}

func (blockingChecker) Ping(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

type delayChecker struct {
	delay time.Duration
}

func (c delayChecker) Ping(ctx context.Context) error {
	select {
	case <-time.After(c.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type panicChecker struct{}

func (panicChecker) Ping(context.Context) error {
	panic("dependency should not be checked")
}
