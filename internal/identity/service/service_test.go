package service

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNewReturnsServiceAndError(t *testing.T) {
	newType := reflect.TypeOf(New)
	if newType.NumOut() != 2 {
		t.Fatalf("New output count = %d, want 2", newType.NumOut())
	}
	if newType.Out(0) != reflect.TypeOf((*Service)(nil)) {
		t.Fatal("New first output is not *Service")
	}
	if newType.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatal("New second output is not error")
	}
}

func TestNewStoresDependenciesAndConfiguration(t *testing.T) {
	repository := repositoryPortStub{}
	passwordHasher := &passwordHasherPortStub{}
	accessTokens := &accessTokenManagerPortStub{}
	refreshTokens := &refreshTokenGeneratorPortStub{}
	clock := &clockPortStub{}
	dependencies := Dependencies{
		Repository:            repository,
		PasswordHasher:        passwordHasher,
		AccessTokenManager:    accessTokens,
		RefreshTokenGenerator: refreshTokens,
		Clock:                 clock,
	}
	configuration := Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	service, err := New(dependencies, configuration)
	if err != nil {
		t.Fatalf("New() returned error type %T for valid configuration", err)
	}

	if service.repository != repository {
		t.Fatal("New() did not retain Repository")
	}
	if service.passwordHasher != passwordHasher {
		t.Fatal("New() did not retain PasswordHasher")
	}
	if service.accessTokenManager != accessTokens {
		t.Fatal("New() did not retain AccessTokenManager")
	}
	if service.refreshTokenGenerator != refreshTokens {
		t.Fatal("New() did not retain RefreshTokenGenerator")
	}
	if service.clock != clock {
		t.Fatal("New() did not retain Clock")
	}
	if service.accessTokenTTL != configuration.AccessTokenTTL {
		t.Fatalf("New() access token TTL = %v, want %v", service.accessTokenTTL, configuration.AccessTokenTTL)
	}
	if service.refreshTokenTTL != configuration.RefreshTokenTTL {
		t.Fatalf("New() refresh token TTL = %v, want %v", service.refreshTokenTTL, configuration.RefreshTokenTTL)
	}
}

func TestNewRejectsInvalidDependenciesAndConfiguration(t *testing.T) {
	validDependencies := serviceTestDependencies()
	validConfig := serviceTestConfig()

	missingRepository := validDependencies
	missingRepository.Repository = nil
	var typedNilRepository *repositoryPortStub
	typedNilRepositoryDependencies := validDependencies
	typedNilRepositoryDependencies.Repository = typedNilRepository

	missingPasswordHasher := validDependencies
	missingPasswordHasher.PasswordHasher = nil
	var typedNilPasswordHasher *passwordHasherPortStub
	typedNilPasswordHasherDependencies := validDependencies
	typedNilPasswordHasherDependencies.PasswordHasher = typedNilPasswordHasher

	missingAccessTokens := validDependencies
	missingAccessTokens.AccessTokenManager = nil
	var typedNilAccessTokens *accessTokenManagerPortStub
	typedNilAccessTokenDependencies := validDependencies
	typedNilAccessTokenDependencies.AccessTokenManager = typedNilAccessTokens

	missingRefreshTokens := validDependencies
	missingRefreshTokens.RefreshTokenGenerator = nil
	var typedNilRefreshTokens *refreshTokenGeneratorPortStub
	typedNilRefreshTokenDependencies := validDependencies
	typedNilRefreshTokenDependencies.RefreshTokenGenerator = typedNilRefreshTokens

	missingClock := validDependencies
	missingClock.Clock = nil
	var typedNilClock *clockPortStub
	typedNilClockDependencies := validDependencies
	typedNilClockDependencies.Clock = typedNilClock

	tests := []struct {
		name         string
		dependencies Dependencies
		config       Config
	}{
		{name: "missing repository", dependencies: missingRepository, config: validConfig},
		{name: "typed nil repository", dependencies: typedNilRepositoryDependencies, config: validConfig},
		{name: "missing password hasher", dependencies: missingPasswordHasher, config: validConfig},
		{name: "typed nil password hasher", dependencies: typedNilPasswordHasherDependencies, config: validConfig},
		{name: "missing access token manager", dependencies: missingAccessTokens, config: validConfig},
		{name: "typed nil access token manager", dependencies: typedNilAccessTokenDependencies, config: validConfig},
		{name: "missing refresh token generator", dependencies: missingRefreshTokens, config: validConfig},
		{name: "typed nil refresh token generator", dependencies: typedNilRefreshTokenDependencies, config: validConfig},
		{name: "missing clock", dependencies: missingClock, config: validConfig},
		{name: "typed nil clock", dependencies: typedNilClockDependencies, config: validConfig},
		{
			name:         "zero access token TTL",
			dependencies: validDependencies,
			config:       Config{AccessTokenTTL: 0, RefreshTokenTTL: 30 * 24 * time.Hour},
		},
		{
			name:         "negative access token TTL",
			dependencies: validDependencies,
			config:       Config{AccessTokenTTL: -time.Second, RefreshTokenTTL: 30 * 24 * time.Hour},
		},
		{
			name:         "refresh token TTL equals access token TTL",
			dependencies: validDependencies,
			config:       Config{AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: 15 * time.Minute},
		},
		{
			name:         "refresh token TTL below access token TTL",
			dependencies: validDependencies,
			config:       Config{AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: 14 * time.Minute},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := New(tt.dependencies, tt.config)

			if service != nil {
				t.Fatal("New() returned a service for invalid configuration")
			}
			if !errors.Is(err, ErrInvalidServiceConfiguration) {
				t.Fatalf("New() error type = %T, want ErrInvalidServiceConfiguration", err)
			}
			if err.Error() != ErrInvalidServiceConfiguration.Error() {
				t.Fatal("New() did not return the stable safe configuration message")
			}
			assertServiceConfigurationErrorOmitsDetails(t, err, tt.config)
		})
	}
}

func serviceTestDependencies() Dependencies {
	return Dependencies{
		Repository:            repositoryPortStub{},
		PasswordHasher:        &passwordHasherPortStub{},
		AccessTokenManager:    &accessTokenManagerPortStub{},
		RefreshTokenGenerator: &refreshTokenGeneratorPortStub{},
		Clock:                 &clockPortStub{},
	}
}

func serviceTestConfig() Config {
	return Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}
}

func assertServiceConfigurationErrorOmitsDetails(t *testing.T, err error, config Config) {
	t.Helper()

	message := strings.ToLower(err.Error())
	for _, forbidden := range []string{
		"repository", "password", "access token", "refresh token", "clock",
		strings.ToLower(config.AccessTokenTTL.String()),
		strings.ToLower(config.RefreshTokenTTL.String()),
	} {
		if forbidden != "" && strings.Contains(message, forbidden) {
			t.Fatal("New() error exposed dependency identity or configuration value")
		}
	}
}

type passwordHasherPortStub struct{}

func (*passwordHasherPortStub) Hash(string) (string, error)  { return "", nil }
func (*passwordHasherPortStub) Compare(string, string) error { return nil }
func (*passwordHasherPortStub) DummyHash() string            { return "" }
func (*passwordHasherPortStub) DummyCandidate() string       { return "" }

type accessTokenManagerPortStub struct{}

func (*accessTokenManagerPortStub) GenerateJWTID() (string, error) { return "", nil }
func (*accessTokenManagerPortStub) Sign(int64, int64, time.Time, time.Time, string) (string, error) {
	return "", nil
}

type refreshTokenGeneratorPortStub struct{}

func (*refreshTokenGeneratorPortStub) Generate() (string, [32]byte, error) {
	return "", [32]byte{}, nil
}
func (*refreshTokenGeneratorPortStub) Format(int64, string) (string, error) {
	return "", nil
}
func (*refreshTokenGeneratorPortStub) Parse(string) (int64, [32]byte, error) {
	return 0, [32]byte{}, nil
}
func (*refreshTokenGeneratorPortStub) Match([32]byte, [32]byte) bool { return false }

type clockPortStub struct{}

func (*clockPortStub) Now() time.Time { return time.Time{} }
