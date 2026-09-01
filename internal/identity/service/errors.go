package service

import "errors"

var (
	ErrEmailExists = errors.New("email already exists")
	ErrNotFound    = errors.New("identity record not found")
	ErrInternal    = errors.New("identity internal error")
)
