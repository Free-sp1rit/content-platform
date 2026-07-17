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
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	health := New(gateChecker{started: started, release: release}, gateChecker{started: started, release: release}, time.Second, time.Second)
	done := make(chan Readiness, 1)
	go func() {
		done <- health.Readiness(context.Background())
	}()

	for range 2 {
		select {
		case <-started:
		case <-time.After(250 * time.Millisecond):
			t.Fatal("both dependency checks did not start concurrently")
		}
	}
	close(release)

	select {
	case got := <-done:
		if got.Status != Ready {
			t.Fatalf("Readiness() = %#v", got)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Readiness() did not complete after releasing checkers")
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

type gateChecker struct {
	started chan<- struct{}
	release <-chan struct{}
}

func (c gateChecker) Ping(ctx context.Context) error {
	c.started <- struct{}{}
	select {
	case <-c.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type panicChecker struct{}

func (panicChecker) Ping(context.Context) error {
	panic("dependency should not be checked")
}
