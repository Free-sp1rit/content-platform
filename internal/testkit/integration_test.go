//go:build integration

package testkit

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	databaseURLPolicyProbeEnv     = "TESTKIT_DATABASE_URL_POLICY_PROBE"
	databaseURLPolicyExpectedEnv  = "TESTKIT_DATABASE_URL_POLICY_EXPECTED"
	redisAddressPolicyProbeEnv    = "TESTKIT_REDIS_ADDRESS_POLICY_PROBE"
	redisAddressPolicyExpectedEnv = "TESTKIT_REDIS_ADDRESS_POLICY_EXPECTED"
)

func TestIntegrationMakeTargetsClearAmbientGOFLAGS(t *testing.T) {
	repositoryRoot := filepath.Join("..", "..")
	tests := []struct {
		name       string
		target     string
		wantRecipe string
	}{
		{
			name:       "full integration",
			target:     "test-integration",
			wantRecipe: "GOFLAGS= TEST_DATABASE_REQUIRED=1 TEST_REDIS_REQUIRED=1 go test -count=1 -tags=integration ./...",
		},
		{
			name:       "PostgreSQL integration",
			target:     "test-integration-postgres",
			wantRecipe: "GOFLAGS= TEST_DATABASE_REQUIRED=1 go test -count=1 -tags=integration ./internal/infra/postgres/... ./internal/testkit/...",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command("make", "-n", "-C", repositoryRoot, test.target)
			command.Env = makePolicyEnvironment()
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("render %s recipe: %v\n%s", test.target, err, output)
			}
			if !strings.Contains(string(output), test.wantRecipe) {
				t.Fatalf("%s recipe does not explicitly clear GOFLAGS", test.target)
			}
		})
	}
}

func makePolicyEnvironment() []string {
	environment := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "GOFLAGS", "TEST_DATABASE_URL", "TEST_REDIS_ADDR":
			continue
		}
		environment = append(environment, entry)
	}
	return append(
		environment,
		"GOFLAGS=-run=^$",
		"TEST_DATABASE_URL=postgres://dummy.invalid/content",
		"TEST_REDIS_ADDR=redis.invalid:6379",
	)
}

func TestPolicyProbesDoNotDiscloseConfiguredValues(t *testing.T) {
	tests := []struct {
		name          string
		probeTest     string
		actualValue   string
		expectedValue string
		environment   func(string, bool, bool, string) []string
	}{
		{
			name:          "database URL",
			probeTest:     "TestDatabaseURLPolicyProbe",
			actualValue:   "postgres://actual-user:actual-password@example.invalid/content",
			expectedValue: "postgres://expected-user:expected-password@example.invalid/content",
			environment:   databaseURLPolicyEnvironment,
		},
		{
			name:          "Redis address",
			probeTest:     "TestRedisAddressPolicyProbe",
			actualValue:   "actual-password.redis.invalid:6379",
			expectedValue: "expected-password.redis.invalid:6379",
			environment:   redisAddressPolicyEnvironment,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^"+test.probeTest+"$", "-test.v")
			command.Env = test.environment(test.actualValue, true, false, test.expectedValue)
			output, err := command.CombinedOutput()

			var exitError *exec.ExitError
			if err == nil {
				t.Fatal("policy probe succeeded with mismatched configured values")
			}
			if !errors.As(err, &exitError) {
				t.Fatal("policy probe subprocess did not report a test failure")
			}
			if !strings.Contains(string(output), "--- FAIL: "+test.probeTest) {
				t.Fatal("policy probe did not report the expected failure state")
			}
			if strings.Contains(string(output), test.actualValue) || strings.Contains(string(output), test.expectedValue) {
				t.Fatal("policy probe disclosed a configured value")
			}
		})
	}
}

func TestDatabaseURLPolicy(t *testing.T) {
	tests := []struct {
		name          string
		databaseURL   string
		setURL        bool
		required      bool
		wantFailure   bool
		wantOutput    string
		wantTestState string
		expectedValue string
	}{
		{
			name:          "default missing skips",
			wantOutput:    "TEST_DATABASE_URL is not set; skipping PostgreSQL integration test",
			wantTestState: "--- SKIP: TestDatabaseURLPolicyProbe",
		},
		{
			name:          "default Unicode whitespace skips",
			databaseURL:   "\u00a0",
			setURL:        true,
			wantOutput:    "TEST_DATABASE_URL is not set; skipping PostgreSQL integration test",
			wantTestState: "--- SKIP: TestDatabaseURLPolicyProbe",
		},
		{
			name:          "required missing fails",
			required:      true,
			wantFailure:   true,
			wantOutput:    "TEST_DATABASE_URL is required",
			wantTestState: "--- FAIL: TestDatabaseURLPolicyProbe",
		},
		{
			name:          "required Unicode whitespace fails",
			databaseURL:   "\u00a0",
			setURL:        true,
			required:      true,
			wantFailure:   true,
			wantOutput:    "TEST_DATABASE_URL is required",
			wantTestState: "--- FAIL: TestDatabaseURLPolicyProbe",
		},
		{
			name:          "default valid value",
			databaseURL:   "  postgres://example.test/content  ",
			setURL:        true,
			wantTestState: "--- PASS: TestDatabaseURLPolicyProbe",
			expectedValue: "postgres://example.test/content",
		},
		{
			name:          "required valid value",
			databaseURL:   "  postgres://example.test/content  ",
			setURL:        true,
			required:      true,
			wantTestState: "--- PASS: TestDatabaseURLPolicyProbe",
			expectedValue: "postgres://example.test/content",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestDatabaseURLPolicyProbe$", "-test.v")
			command.Env = databaseURLPolicyEnvironment(test.databaseURL, test.setURL, test.required, test.expectedValue)
			output, err := command.CombinedOutput()

			var exitError *exec.ExitError
			if err != nil && !errors.As(err, &exitError) {
				t.Fatalf("run DatabaseURL policy probe: %v", err)
			}
			if test.wantFailure && err == nil {
				t.Fatalf("DatabaseURL policy probe succeeded, want failure; output:\n%s", output)
			}
			if !test.wantFailure && err != nil {
				t.Fatalf("DatabaseURL policy probe failed with exit %d; output:\n%s", exitError.ExitCode(), output)
			}
			if test.wantOutput != "" && !strings.Contains(string(output), test.wantOutput) {
				t.Fatalf("DatabaseURL policy probe output = %q, want substring %q", output, test.wantOutput)
			}
			if !strings.Contains(string(output), test.wantTestState) {
				t.Fatalf("DatabaseURL policy probe output = %q, want test state %q", output, test.wantTestState)
			}
		})
	}
}

func TestDatabaseURLPolicyProbe(t *testing.T) {
	if os.Getenv(databaseURLPolicyProbeEnv) != "1" {
		return
	}
	got := DatabaseURL(t)
	if want := os.Getenv(databaseURLPolicyExpectedEnv); got != want {
		t.Fatal("DatabaseURL() returned an unexpected value")
	}
}

func databaseURLPolicyEnvironment(databaseURL string, setURL, required bool, expectedValue string) []string {
	environment := make([]string, 0, len(os.Environ())+4)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "TEST_DATABASE_URL", testDatabaseRequiredEnv, databaseURLPolicyProbeEnv, databaseURLPolicyExpectedEnv:
			continue
		}
		environment = append(environment, entry)
	}
	environment = append(environment, databaseURLPolicyProbeEnv+"=1")
	if setURL {
		environment = append(environment, "TEST_DATABASE_URL="+databaseURL)
	}
	if required {
		environment = append(environment, testDatabaseRequiredEnv+"=1")
	}
	if expectedValue != "" {
		environment = append(environment, databaseURLPolicyExpectedEnv+"="+expectedValue)
	}
	return environment
}

func TestRedisAddressPolicy(t *testing.T) {
	tests := []struct {
		name          string
		redisAddress  string
		setAddress    bool
		required      bool
		wantFailure   bool
		wantOutput    string
		wantTestState string
		expectedValue string
	}{
		{
			name:          "default missing skips",
			wantOutput:    "TEST_REDIS_ADDR is not set; skipping Redis integration test",
			wantTestState: "--- SKIP: TestRedisAddressPolicyProbe",
		},
		{
			name:          "default Unicode whitespace skips",
			redisAddress:  "\u00a0",
			setAddress:    true,
			wantOutput:    "TEST_REDIS_ADDR is not set; skipping Redis integration test",
			wantTestState: "--- SKIP: TestRedisAddressPolicyProbe",
		},
		{
			name:          "required missing fails",
			required:      true,
			wantFailure:   true,
			wantOutput:    "TEST_REDIS_ADDR is required",
			wantTestState: "--- FAIL: TestRedisAddressPolicyProbe",
		},
		{
			name:          "required Unicode whitespace fails",
			redisAddress:  "\u00a0",
			setAddress:    true,
			required:      true,
			wantFailure:   true,
			wantOutput:    "TEST_REDIS_ADDR is required",
			wantTestState: "--- FAIL: TestRedisAddressPolicyProbe",
		},
		{
			name:          "default valid value",
			redisAddress:  "  redis.example.test:6379  ",
			setAddress:    true,
			wantTestState: "--- PASS: TestRedisAddressPolicyProbe",
			expectedValue: "redis.example.test:6379",
		},
		{
			name:          "required valid value",
			redisAddress:  "  redis.example.test:6379  ",
			setAddress:    true,
			required:      true,
			wantTestState: "--- PASS: TestRedisAddressPolicyProbe",
			expectedValue: "redis.example.test:6379",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestRedisAddressPolicyProbe$", "-test.v")
			command.Env = redisAddressPolicyEnvironment(
				test.redisAddress,
				test.setAddress,
				test.required,
				test.expectedValue,
			)
			output, err := command.CombinedOutput()

			var exitError *exec.ExitError
			if err != nil && !errors.As(err, &exitError) {
				t.Fatalf("run RedisAddress policy probe: %v", err)
			}
			if test.wantFailure && err == nil {
				t.Fatalf("RedisAddress policy probe succeeded, want failure; output:\n%s", output)
			}
			if !test.wantFailure && err != nil {
				t.Fatalf("RedisAddress policy probe failed with exit %d; output:\n%s", exitError.ExitCode(), output)
			}
			if test.wantOutput != "" && !strings.Contains(string(output), test.wantOutput) {
				t.Fatalf("RedisAddress policy probe output = %q, want substring %q", output, test.wantOutput)
			}
			if !strings.Contains(string(output), test.wantTestState) {
				t.Fatalf("RedisAddress policy probe output = %q, want test state %q", output, test.wantTestState)
			}
		})
	}
}

func TestRedisAddressPolicyProbe(t *testing.T) {
	if os.Getenv(redisAddressPolicyProbeEnv) != "1" {
		return
	}
	got := RedisAddress(t)
	if want := os.Getenv(redisAddressPolicyExpectedEnv); got != want {
		t.Fatal("RedisAddress() returned an unexpected value")
	}
}

func redisAddressPolicyEnvironment(redisAddress string, setAddress, required bool, expectedValue string) []string {
	environment := make([]string, 0, len(os.Environ())+4)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "TEST_REDIS_ADDR", testRedisRequiredEnv, redisAddressPolicyProbeEnv, redisAddressPolicyExpectedEnv:
			continue
		}
		environment = append(environment, entry)
	}
	environment = append(environment, redisAddressPolicyProbeEnv+"=1")
	if setAddress {
		environment = append(environment, "TEST_REDIS_ADDR="+redisAddress)
	}
	if required {
		environment = append(environment, testRedisRequiredEnv+"=1")
	}
	if expectedValue != "" {
		environment = append(environment, redisAddressPolicyExpectedEnv+"="+expectedValue)
	}
	return environment
}
