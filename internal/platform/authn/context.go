package authn

import "context"

type Principal struct {
	UserID    int64
	SessionID int64
}

type principalContextKey struct{}

func WithContext(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func FromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}
