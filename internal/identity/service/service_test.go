package service

import (
	"testing"
	"time"
)

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

	service := New(dependencies, configuration)

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
