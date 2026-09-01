package service

import "time"

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

func New(dependencies Dependencies, config Config) *Service {
	return &Service{
		repository:            dependencies.Repository,
		passwordHasher:        dependencies.PasswordHasher,
		accessTokenManager:    dependencies.AccessTokenManager,
		refreshTokenGenerator: dependencies.RefreshTokenGenerator,
		clock:                 dependencies.Clock,
		accessTokenTTL:        config.AccessTokenTTL,
		refreshTokenTTL:       config.RefreshTokenTTL,
	}
}
