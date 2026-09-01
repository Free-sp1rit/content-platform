package password

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestNewValidatesCostAndBuildsMatchingDummyHash(t *testing.T) {
	for _, cost := range []int{9, 10, 15, 16} {
		t.Run(strconv.Itoa(cost), func(t *testing.T) {
			hasher, err := New(cost)
			if cost < 10 || cost > 15 {
				if err == nil {
					t.Fatalf("New(%d) succeeded", cost)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%d) error = %v", cost, err)
			}

			gotCost, err := bcrypt.Cost([]byte(hasher.DummyHash()))
			if err != nil {
				t.Fatalf("dummy hash is invalid: %v", err)
			}
			if gotCost != cost {
				t.Fatalf("dummy hash cost = %d, want %d", gotCost, cost)
			}
			if err := hasher.Compare(hasher.DummyHash(), hasher.DummyCandidate()); err != nil {
				t.Fatalf("Compare(dummy) error = %v", err)
			}
		})
	}

	hasher, err := New(10)
	if err != nil {
		t.Fatalf("New(10) error = %v", err)
	}
	if size := len(hasher.DummyCandidate()); size < 8 || size > 72 {
		t.Fatalf("DummyCandidate length = %d, want 8..72 bytes", size)
	}
	if hasher.DummyCandidate() != hasher.DummyCandidate() {
		t.Fatal("DummyCandidate() is not fixed")
	}
}

func TestHashAndCompare(t *testing.T) {
	hasher, err := New(10)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	hash, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	gotCost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("Cost() error = %v", err)
	}
	if gotCost != 10 {
		t.Fatalf("Hash() cost = %d, want 10", gotCost)
	}
	if err := hasher.Compare(hash, "correct horse battery staple"); err != nil {
		t.Fatalf("Compare(valid) error = %v", err)
	}
	if err := hasher.Compare(hash, "wrong candidate"); err == nil {
		t.Fatal("Compare(wrong) succeeded")
	}
}

func TestCompareRejectsInvalidHashMetadata(t *testing.T) {
	hasher, err := New(10)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	const candidate = "candidate-for-cost-test"
	lowCostHash, err := bcrypt.GenerateFromPassword([]byte(candidate), 9)
	if err != nil {
		t.Fatalf("GenerateFromPassword(cost 9) error = %v", err)
	}

	tests := []struct {
		name string
		hash string
	}{
		{name: "malformed hash", hash: "malformed-hash-do-not-log"},
		{name: "cost below application minimum", hash: string(lowCostHash)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := hasher.Compare(tt.hash, candidate)
			if !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("Compare() error = %v, want ErrInvalidHash", err)
			}
			if strings.Contains(err.Error(), tt.hash) || strings.Contains(err.Error(), candidate) {
				t.Fatal("Compare() error exposed hash or candidate")
			}
		})
	}
}

func TestCompareRejectsExcessiveHashCost(t *testing.T) {
	hasher, err := New(10)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	const candidate = "candidate-for-cost-test"
	baseHash, err := bcrypt.GenerateFromPassword([]byte(candidate), 10)
	if err != nil {
		t.Fatalf("GenerateFromPassword(cost 10) error = %v", err)
	}
	highCostHash := strings.Replace(string(baseHash), "$10$", "$16$", 1)
	if highCostHash == string(baseHash) {
		t.Fatal("test hash cost field was not changed")
	}

	err = hasher.Compare(highCostHash, candidate)

	if !errors.Is(err, ErrInvalidHash) {
		t.Errorf("Compare() error = %v, want ErrInvalidHash", err)
	}
	if err != nil && (strings.Contains(err.Error(), highCostHash) || strings.Contains(err.Error(), candidate)) {
		t.Fatal("Compare() error exposed hash or candidate")
	}
}

func TestHashEnforcesBcryptByteLimit(t *testing.T) {
	hasher, err := New(10)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := hasher.Hash(strings.Repeat("a", 72)); err != nil {
		t.Fatalf("Hash(72 bytes) error = %v", err)
	}
	if _, err := hasher.Hash(strings.Repeat("a", 73)); err == nil {
		t.Fatal("Hash(73 bytes) succeeded")
	}

	hash, err := hasher.Hash("valid password")
	if err != nil {
		t.Fatalf("Hash(valid password) error = %v", err)
	}
	if err := hasher.Compare(hash, strings.Repeat("a", 73)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Compare(73 bytes) error = %v, want ErrPasswordTooLong", err)
	}
}

func TestErrorsDoNotExposePasswordOrHash(t *testing.T) {
	hasher, err := New(10)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tooLong := strings.Repeat("password-do-not-log-", 4)
	if _, err := hasher.Hash(tooLong); err == nil {
		t.Fatal("Hash(long password) succeeded")
	} else if strings.Contains(err.Error(), tooLong) || strings.Contains(err.Error(), "password-do-not-log") {
		t.Fatal("Hash() error exposed password")
	}

	malformedHash := "malformed-hash-do-not-log"
	candidate := "candidate-do-not-log"
	if err := hasher.Compare(malformedHash, candidate); err == nil {
		t.Fatal("Compare(malformed hash) succeeded")
	} else if strings.Contains(err.Error(), malformedHash) || strings.Contains(err.Error(), candidate) || strings.Contains(err.Error(), "do-not-log") {
		t.Fatal("Compare() error exposed hash or password")
	}
}
