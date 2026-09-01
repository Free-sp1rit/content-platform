package password

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

const dummyCandidate = "content-platform-dummy-password"

var (
	ErrInvalidCost      = errors.New("bcrypt cost must be between 10 and 15")
	ErrPasswordTooLong  = errors.New("password exceeds bcrypt 72-byte limit")
	ErrPasswordMismatch = errors.New("password comparison failed")
	ErrInvalidHash      = errors.New("password hash is invalid")
)

type Bcrypt struct {
	cost      int
	dummyHash string
}

func New(cost int) (*Bcrypt, error) {
	if cost < 10 || cost > 15 {
		return nil, ErrInvalidCost
	}
	dummyHash, err := bcrypt.GenerateFromPassword([]byte(dummyCandidate), cost)
	if err != nil {
		return nil, errors.New("generate dummy password hash")
	}
	return &Bcrypt{cost: cost, dummyHash: string(dummyHash)}, nil
}

func (b *Bcrypt) Hash(candidate string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(candidate), b.cost)
	if err != nil {
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return "", ErrPasswordTooLong
		}
		return "", errors.New("hash password")
	}
	return string(hash), nil
}

func (b *Bcrypt) Compare(hash, candidate string) error {
	if len(candidate) > 72 {
		return ErrPasswordTooLong
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil || cost < 10 || cost > 15 {
		return ErrInvalidHash
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(candidate))
	if err == nil {
		return nil
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrPasswordMismatch
	}
	return ErrInvalidHash
}

func (b *Bcrypt) DummyHash() string {
	return b.dummyHash
}

func (b *Bcrypt) DummyCandidate() string {
	return dummyCandidate
}
