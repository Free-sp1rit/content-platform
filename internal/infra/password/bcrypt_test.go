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
			matched, err := hasher.Compare(hasher.DummyHash(), hasher.DummyCandidate())
			if err != nil {
				t.Fatalf("Compare(dummy) error = %v", err)
			}
			if !matched {
				t.Fatal("Compare(dummy) matched = false")
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
	matched, err := hasher.Compare(hash, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Compare(valid) error = %v", err)
	}
	if !matched {
		t.Fatal("Compare(valid) matched = false")
	}
	matched, err = hasher.Compare(hash, "wrong candidate")
	if err != nil {
		t.Fatalf("Compare(wrong) error = %v, want normal mismatch", err)
	}
	if matched {
		t.Fatal("Compare(wrong) matched = true")
	}
}

func TestCompareTreatsConfiguredCostMismatchAsOrdinaryMismatch(t *testing.T) {
	const candidate = "correct horse battery staple"
	storedHash, err := bcrypt.GenerateFromPassword([]byte(candidate), 10)
	if err != nil {
		t.Fatalf("GenerateFromPassword(cost 10) error = %v", err)
	}
	hasher, err := New(12)
	if err != nil {
		t.Fatalf("New(12) error = %v", err)
	}

	matched, err := hasher.Compare(string(storedHash), candidate)

	if err != nil {
		t.Fatalf("Compare(cost mismatch) error = %v, want ordinary mismatch", err)
	}
	if matched {
		t.Fatal("Compare(cost mismatch) matched = true, want false")
	}
}

func TestCompareInvalidInputsExerciseConfiguredDummyPath(t *testing.T) {
	const candidate = "candidate-for-dummy-path"
	hasher, err := New(10)
	if err != nil {
		t.Fatalf("New(10) error = %v", err)
	}
	validHash, err := bcrypt.GenerateFromPassword([]byte(candidate), 10)
	if err != nil {
		t.Fatalf("GenerateFromPassword(cost 10) error = %v", err)
	}
	lowCostHash, err := bcrypt.GenerateFromPassword([]byte(candidate), 9)
	if err != nil {
		t.Fatalf("GenerateFromPassword(cost 9) error = %v", err)
	}
	highCostHash := strings.Replace(string(validHash), "$10$", "$16$", 1)
	hasher.dummyHash = "damaged-dummy-hash-do-not-log"

	tests := []struct {
		name      string
		hash      string
		candidate string
	}{
		{name: "malformed hash", hash: "malformed-stored-hash-do-not-log", candidate: candidate},
		{name: "cost below policy", hash: string(lowCostHash), candidate: candidate},
		{name: "cost above policy", hash: highCostHash, candidate: candidate},
		{name: "candidate above bcrypt boundary", hash: string(validHash), candidate: strings.Repeat("p", 73)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, err := hasher.Compare(tt.hash, tt.candidate)
			if err == nil {
				t.Fatal("Compare() succeeded with a damaged configured dummy path")
			}
			if matched {
				t.Fatal("Compare() matched with a damaged configured dummy path")
			}
			if errors.Is(err, ErrInvalidHash) || errors.Is(err, ErrPasswordTooLong) {
				t.Fatal("Compare() returned the input classification before exercising the configured dummy path")
			}
			for _, private := range []string{tt.hash, tt.candidate, hasher.dummyHash, "do-not-log"} {
				if private != "" && strings.Contains(err.Error(), private) {
					t.Fatal("Compare() dummy failure exposed private hash or candidate data")
				}
			}
		})
	}
}

func TestCompareInvalidCurrentCostSaltExercisesConfiguredDummyPath(t *testing.T) {
	const candidate = "candidate-for-invalid-salt"
	validHash, err := bcrypt.GenerateFromPassword([]byte(candidate), 10)
	if err != nil {
		t.Fatalf("GenerateFromPassword(cost 10) error = %v", err)
	}
	invalidSaltHash := []byte(validHash)
	invalidSaltHash[7] = '!'
	parsedCost, err := bcrypt.Cost(invalidSaltHash)
	if err != nil {
		t.Fatalf("bcrypt.Cost(current-cost invalid-salt hash) error = %v", err)
	}
	if parsedCost != 10 {
		t.Fatalf("bcrypt.Cost(current-cost invalid-salt hash) = %d, want 10", parsedCost)
	}

	t.Run("returns safe invalid hash classification", func(t *testing.T) {
		hasher, err := New(10)
		if err != nil {
			t.Fatalf("New(10) error type = %T", err)
		}

		matched, err := hasher.Compare(string(invalidSaltHash), candidate)

		if matched {
			t.Fatal("Compare() matched a hash with an invalid bcrypt salt")
		}
		assertCompareErrorDoesNotExposePrivateData(t, err, string(invalidSaltHash), candidate, hasher.dummyHash)
		if !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("Compare() error type = %T, want ErrInvalidHash", err)
		}
	})

	t.Run("exercises configured dummy path", func(t *testing.T) {
		hasher, err := New(10)
		if err != nil {
			t.Fatalf("New(10) error type = %T", err)
		}
		hasher.dummyHash = "damaged-dummy-hash-do-not-log"

		matched, err := hasher.Compare(string(invalidSaltHash), candidate)

		if matched {
			t.Fatal("Compare() matched a hash with an invalid bcrypt salt")
		}
		assertCompareErrorDoesNotExposePrivateData(t, err, string(invalidSaltHash), candidate, hasher.dummyHash, "do-not-log")
		if !errors.Is(err, errDummyCompare) {
			t.Fatalf("Compare() error type = %T, want proof that the configured dummy path ran", err)
		}
	})
}

func assertCompareErrorDoesNotExposePrivateData(t *testing.T, err error, privateValues ...string) {
	t.Helper()
	if err == nil {
		return
	}
	for _, private := range privateValues {
		if private != "" && strings.Contains(err.Error(), private) {
			t.Fatal("Compare() error exposed private hash or candidate data")
		}
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
			matched, err := hasher.Compare(tt.hash, candidate)
			if !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("Compare() error = %v, want ErrInvalidHash", err)
			}
			if matched {
				t.Fatal("Compare() matched an invalid hash")
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

	matched, err := hasher.Compare(highCostHash, candidate)

	if !errors.Is(err, ErrInvalidHash) {
		t.Errorf("Compare() error = %v, want ErrInvalidHash", err)
	}
	if matched {
		t.Error("Compare() matched an excessive-cost hash")
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
	matched, err := hasher.Compare(hash, strings.Repeat("a", 73))
	if !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Compare(73 bytes) error = %v, want ErrPasswordTooLong", err)
	}
	if matched {
		t.Fatal("Compare(73 bytes) matched = true")
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
	if matched, err := hasher.Compare(malformedHash, candidate); err == nil {
		t.Fatal("Compare(malformed hash) succeeded")
	} else if matched {
		t.Fatal("Compare(malformed hash) matched = true")
	} else if strings.Contains(err.Error(), malformedHash) || strings.Contains(err.Error(), candidate) || strings.Contains(err.Error(), "do-not-log") {
		t.Fatal("Compare() error exposed hash or password")
	}
}
