package domain

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-playground/validator/v10"
)

const (
	maxEmailBytes       = 320
	minPasswordBytes    = 8
	maxPasswordBytes    = 72
	maxDisplayNameRunes = 100
	maxBioRunes         = 1000
)

var emailValidator = validator.New()

func NormalizeEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func ValidateEmail(value string) error {
	normalized := NormalizeEmail(value)
	if len(normalized) > maxEmailBytes {
		return errors.New("email must be at most 320 bytes")
	}
	if err := emailValidator.Var(normalized, "required,email"); err != nil {
		return errors.New("email must be a valid email address")
	}
	return nil
}

func ValidateRegistrationPassword(value string) error {
	length := len(value)
	if length < minPasswordBytes || length > maxPasswordBytes {
		return errors.New("password must be between 8 and 72 bytes")
	}
	return nil
}

func NormalizeDisplayName(value string) string {
	return strings.TrimSpace(value)
}

func ValidateDisplayName(value string) error {
	length := utf8.RuneCountInString(NormalizeDisplayName(value))
	if length < 1 || length > maxDisplayNameRunes {
		return errors.New("display name must be between 1 and 100 characters")
	}
	return nil
}

func ValidateBio(value string) error {
	if utf8.RuneCountInString(value) > maxBioRunes {
		return errors.New("bio must be at most 1000 characters")
	}
	return nil
}

func NormalizeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Second)
}
