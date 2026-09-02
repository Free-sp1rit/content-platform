package password

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

const dummyCandidate = "content-platform-dummy-password"

var (
	ErrInvalidCost     = errors.New("bcrypt cost must be between 10 and 15")
	ErrPasswordTooLong = errors.New("password exceeds bcrypt 72-byte limit")
	ErrInvalidHash     = errors.New("password hash is invalid")
	errDummyCompare    = errors.New("bcrypt dummy comparison failed")
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

func (b *Bcrypt) Compare(hash, candidate string) (bool, error) {
	if len(candidate) > 72 {
		return b.rejectAfterDummy(ErrPasswordTooLong)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil || cost < 10 || cost > 15 {
		return b.rejectAfterDummy(ErrInvalidHash)
	}
	// The configured cost is a persistent account-availability invariant.
	// A stored hash at another otherwise valid cost fails as an ordinary
	// mismatch after consuming the current configured dummy workload.
	if cost != b.cost {
		return b.rejectAfterDummy(nil)
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(candidate))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	return b.rejectAfterDummy(ErrInvalidHash)
}

func (b *Bcrypt) rejectAfterDummy(resultErr error) (bool, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(b.dummyHash), []byte(dummyCandidate)); err != nil {
		return false, errDummyCompare
	}
	return false, resultErr
}

func (b *Bcrypt) DummyHash() string {
	return b.dummyHash
}

func (b *Bcrypt) DummyCandidate() string {
	return dummyCandidate
}
