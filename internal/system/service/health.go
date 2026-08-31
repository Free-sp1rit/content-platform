package service

import (
	"context"
	"time"
)

type Checker interface {
	Ping(context.Context) error
}

type Status string

type DependencyState string

const (
	Ready    Status = "ready"
	Degraded Status = "degraded"
	NotReady Status = "not_ready"

	Up   DependencyState = "up"
	Down DependencyState = "down"
)

type Liveness struct {
	Status string `json:"status"`
}

type Readiness struct {
	Status Status                     `json:"status"`
	Checks map[string]DependencyState `json:"checks"`
}

type Service struct {
	postgres        Checker
	redis           Checker
	postgresTimeout time.Duration
	redisTimeout    time.Duration
}

func New(postgres, redis Checker, postgresTimeout, redisTimeout time.Duration) *Service {
	return &Service{
		postgres:        postgres,
		redis:           redis,
		postgresTimeout: postgresTimeout,
		redisTimeout:    redisTimeout,
	}
}

func (s *Service) Liveness(context.Context) Liveness {
	return Liveness{Status: "ok"}
}

func (s *Service) Readiness(ctx context.Context) Readiness {
	results := make(chan dependencyResult, 2)
	go checkDependency(ctx, results, "postgres", s.postgres, s.postgresTimeout)
	go checkDependency(ctx, results, "redis", s.redis, s.redisTimeout)

	checks := make(map[string]DependencyState, 2)
	for range 2 {
		result := <-results
		checks[result.name] = result.state
	}

	status := Ready
	if checks["postgres"] == Down {
		status = NotReady
	} else if checks["redis"] == Down {
		status = Degraded
	}

	return Readiness{Status: status, Checks: checks}
}

type dependencyResult struct {
	name  string
	state DependencyState
}

func checkDependency(ctx context.Context, results chan<- dependencyResult, name string, checker Checker, timeout time.Duration) {
	checkContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	state := Up
	if err := checker.Ping(checkContext); err != nil {
		state = Down
	}
	results <- dependencyResult{name: name, state: state}
}
