package service_test

import (
	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	"github.com/Free-sp1rit/content-platform/internal/infra/clock"
	"github.com/Free-sp1rit/content-platform/internal/infra/password"
	"github.com/Free-sp1rit/content-platform/internal/infra/token"
)

var (
	_ identityservice.PasswordHasher        = (*password.Bcrypt)(nil)
	_ identityservice.AccessTokenManager    = (*token.AccessManager)(nil)
	_ identityservice.RefreshTokenGenerator = (*token.RefreshCodec)(nil)
	_ identityservice.Clock                 = clock.System{}
)
