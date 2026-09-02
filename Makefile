.PHONY: run fmt vet test test-race test-integration test-integration-postgres migrate-up migrate-status migrate-down-one

run:
	go run ./cmd/server

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

vet:
	go vet ./...

test:
	go test ./...

test-race:
	go test -race ./...

test-integration:
	@test -n "$$TEST_DATABASE_URL" || (echo "TEST_DATABASE_URL is required" >&2; exit 1)
	@test -n "$$TEST_REDIS_ADDR" || (echo "TEST_REDIS_ADDR is required" >&2; exit 1)
	GOFLAGS= TEST_DATABASE_REQUIRED=1 TEST_REDIS_REQUIRED=1 go test -count=1 -tags=integration ./...

test-integration-postgres:
	@test -n "$$(printf '%s' "$$TEST_DATABASE_URL" | tr -d '[:space:]')" || (echo "TEST_DATABASE_URL is required" >&2; exit 1)
	GOFLAGS= TEST_DATABASE_REQUIRED=1 go test -count=1 -tags=integration ./internal/infra/postgres/... ./internal/testkit/...

migrate-up:
	go run ./cmd/migrate up

migrate-status:
	go run ./cmd/migrate status

migrate-down-one:
	go run ./cmd/migrate down-one
