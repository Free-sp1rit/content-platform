package service

import (
	"reflect"
	"time"
)

type Dependencies struct {
	Repository            Repository
	PasswordHasher        PasswordHasher
	AccessTokenManager    AccessTokenManager
	RefreshTokenGenerator RefreshTokenGenerator
	Clock                 Clock
}

type Config struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

type Service struct {
	repository            Repository
	passwordHasher        PasswordHasher
	accessTokenManager    AccessTokenManager
	refreshTokenGenerator RefreshTokenGenerator
	clock                 Clock
	accessTokenTTL        time.Duration
	refreshTokenTTL       time.Duration
}

func New(dependencies Dependencies, config Config) (*Service, error) {
	if isNilDependency(dependencies.Repository) ||
		isNilDependency(dependencies.PasswordHasher) ||
		isNilDependency(dependencies.AccessTokenManager) ||
		isNilDependency(dependencies.RefreshTokenGenerator) ||
		isNilDependency(dependencies.Clock) ||
		config.AccessTokenTTL <= 0 ||
		config.RefreshTokenTTL <= config.AccessTokenTTL {
		return nil, ErrInvalidServiceConfiguration
	}

	return &Service{
		repository:            dependencies.Repository,
		passwordHasher:        dependencies.PasswordHasher,
		accessTokenManager:    dependencies.AccessTokenManager,
		refreshTokenGenerator: dependencies.RefreshTokenGenerator,
		clock:                 dependencies.Clock,
		accessTokenTTL:        config.AccessTokenTTL,
		refreshTokenTTL:       config.RefreshTokenTTL,
	}, nil
}

func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
