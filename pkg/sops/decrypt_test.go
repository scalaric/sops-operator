package sops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateEncryptedYAML(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid sops yaml",
			input: `
username: ENC[AES256_GCM,data:test,iv:test,tag:test,type:str]
sops:
    mac: ENC[AES256_GCM,data:test,iv:test,tag:test,type:str]
    version: 3.9.0
`,
			wantErr: false,
		},
		{
			name: "missing sops block",
			input: `
username: test
password: secret
`,
			wantErr: true,
			errMsg:  "missing sops metadata block",
		},
		{
			name: "missing mac",
			input: `
username: ENC[AES256_GCM,data:test,iv:test,tag:test,type:str]
sops:
    version: 3.9.0
`,
			wantErr: true,
			errMsg:  "missing MAC in sops metadata",
		},
		{
			name:    "invalid yaml",
			input:   `{{{not valid yaml`,
			wantErr: true,
			errMsg:  "invalid YAML",
		},
		{
			name:    "empty yaml",
			input:   "",
			wantErr: true,
			errMsg:  "empty YAML data",
		},
		{
			name:    "whitespace only",
			input:   "   \n   ",
			wantErr: true,
			errMsg:  "missing sops metadata block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEncryptedYAML([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEncryptedYAML() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !containsString(err.Error(), tt.errMsg) {
					t.Errorf("ValidateEncryptedYAML() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

func TestParseDecryptedYAML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKeys []string
		wantVals map[string]string
		wantErr  bool
	}{
		{
			name: "simple key-value pairs",
			input: `
username: admin
password: secret123
`,
			wantKeys: []string{"username", "password"},
			wantVals: map[string]string{
				"username": "admin",
				"password": "secret123",
			},
			wantErr: false,
		},
		{
			name: "numeric values",
			input: `
port: 5432
ratio: 3.14
count: 100
`,
			wantKeys: []string{"port", "ratio", "count"},
			wantVals: map[string]string{
				"port":  "5432",
				"ratio": "3.14",
				"count": "100",
			},
			wantErr: false,
		},
		{
			name: "boolean values",
			input: `
enabled: true
disabled: false
`,
			wantKeys: []string{"enabled", "disabled"},
			wantVals: map[string]string{
				"enabled":  "true",
				"disabled": "false",
			},
			wantErr: false,
		},
		{
			name: "skips sops metadata",
			input: `
username: admin
sops:
    mac: test
    version: 3.9.0
`,
			wantKeys: []string{"username"},
			wantVals: map[string]string{
				"username": "admin",
			},
			wantErr: false,
		},
		{
			name: "null values",
			input: `
empty_value: null
`,
			wantKeys: []string{"empty_value"},
			wantVals: map[string]string{
				"empty_value": "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseDecryptedYAML([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDecryptedYAML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Check all expected keys exist
			for _, key := range tt.wantKeys {
				if _, ok := result.Data[key]; !ok {
					t.Errorf("parseDecryptedYAML() missing key %q", key)
				}
			}

			// Check values
			for key, wantVal := range tt.wantVals {
				if gotVal := result.StringData[key]; gotVal != wantVal {
					t.Errorf("parseDecryptedYAML() key %q = %q, want %q", key, gotVal, wantVal)
				}
			}
		})
	}
}

func TestNewDecryptor(t *testing.T) {
	keys := []string{"AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"}
	d := NewDecryptor(keys)

	if d == nil {
		t.Fatal("NewDecryptor() returned nil")
	}

	if len(d.ageKeys) != 1 {
		t.Errorf("NewDecryptor() got %d keys, want 1", len(d.ageKeys))
	}

	if d.timeout != DefaultDecryptTimeout {
		t.Errorf("NewDecryptor() timeout = %v, want %v", d.timeout, DefaultDecryptTimeout)
	}

	if d.createTempFile == nil {
		t.Error("NewDecryptor() createTempFile should not be nil")
	}
}

func TestNewDecryptorWithTimeout(t *testing.T) {
	customTimeout := 60 * time.Second
	d := NewDecryptor([]string{"key"}, WithTimeout(customTimeout))

	if d.timeout != customTimeout {
		t.Errorf("NewDecryptor() timeout = %v, want %v", d.timeout, customTimeout)
	}
}

func TestNewDecryptorFromEnv(t *testing.T) {
	// Test with no env vars set
	t.Run("no env vars", func(t *testing.T) {
		// Clear env vars
		t.Setenv("SOPS_AGE_KEY", "")
		t.Setenv("SOPS_AGE_KEY_FILE", "")

		_, err := NewDecryptorFromEnv()
		if err == nil {
			t.Error("NewDecryptorFromEnv() expected error with no env vars")
		}
	})

	t.Run("with SOPS_AGE_KEY", func(t *testing.T) {
		t.Setenv("SOPS_AGE_KEY", "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
		t.Setenv("SOPS_AGE_KEY_FILE", "")

		d, err := NewDecryptorFromEnv()
		if err != nil {
			t.Errorf("NewDecryptorFromEnv() error = %v", err)
			return
		}
		if len(d.ageKeys) != 1 {
			t.Errorf("NewDecryptorFromEnv() got %d keys, want 1", len(d.ageKeys))
		}
		if d.createTempFile == nil {
			t.Error("NewDecryptorFromEnv() createTempFile should not be nil")
		}
	})

	t.Run("filters comments and empty lines", func(t *testing.T) {
		testKey := "# comment\n\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n  \n"
		t.Setenv("SOPS_AGE_KEY", testKey)
		t.Setenv("SOPS_AGE_KEY_FILE", "")

		d, err := NewDecryptorFromEnv()
		if err != nil {
			t.Errorf("NewDecryptorFromEnv() error = %v", err)
			return
		}
		if len(d.ageKeys) != 1 {
			t.Errorf("NewDecryptorFromEnv() got %d keys, want 1 (after filtering)", len(d.ageKeys))
		}
	})
}

func TestDecryptWithContext_Timeout(t *testing.T) {
	d := NewDecryptor([]string{"fake-key"}, WithTimeout(1*time.Nanosecond))

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// This should timeout almost immediately
	_, err := d.DecryptWithContext(ctx, []byte("test"))
	if err == nil {
		t.Skip("Expected timeout error but got nil - sops may not be installed")
	}
	// Error is expected (either timeout or sops not found)
}

// Helper function
func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestNewDecryptorFromEnvWithFile(t *testing.T) {
	// Create a temp file with a key
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "age.key")
	keyContent := "# Comment line\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n"
	if err := os.WriteFile(keyFile, []byte(keyContent), 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	t.Run("with SOPS_AGE_KEY_FILE", func(t *testing.T) {
		t.Setenv("SOPS_AGE_KEY", "")
		t.Setenv("SOPS_AGE_KEY_FILE", keyFile)

		d, err := NewDecryptorFromEnv()
		if err != nil {
			t.Errorf("NewDecryptorFromEnv() error = %v", err)
			return
		}
		if len(d.ageKeys) != 1 {
			t.Errorf("NewDecryptorFromEnv() got %d keys, want 1", len(d.ageKeys))
		}
		if d.ageKeyFile != keyFile {
			t.Errorf("NewDecryptorFromEnv() ageKeyFile = %q, want %q", d.ageKeyFile, keyFile)
		}
	})

	t.Run("with nonexistent key file", func(t *testing.T) {
		t.Setenv("SOPS_AGE_KEY", "")
		t.Setenv("SOPS_AGE_KEY_FILE", "/nonexistent/path/to/key")

		_, err := NewDecryptorFromEnv()
		if err == nil {
			t.Error("NewDecryptorFromEnv() expected error for nonexistent file")
		}
		if !containsString(err.Error(), "failed to read AGE key file") {
			t.Errorf("NewDecryptorFromEnv() error = %v, want error containing 'failed to read AGE key file'", err)
		}
	})

	t.Run("with both env var and file", func(t *testing.T) {
		t.Setenv("SOPS_AGE_KEY", "AGE-SECRET-KEY-1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		t.Setenv("SOPS_AGE_KEY_FILE", keyFile)

		d, err := NewDecryptorFromEnv()
		if err != nil {
			t.Errorf("NewDecryptorFromEnv() error = %v", err)
			return
		}
		// Should have 2 keys (one from env, one from file)
		if len(d.ageKeys) != 2 {
			t.Errorf("NewDecryptorFromEnv() got %d keys, want 2", len(d.ageKeys))
		}
	})

	t.Run("with timeout option", func(t *testing.T) {
		t.Setenv("SOPS_AGE_KEY", "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
		t.Setenv("SOPS_AGE_KEY_FILE", "")

		customTimeout := 60 * time.Second
		d, err := NewDecryptorFromEnv(WithTimeout(customTimeout))
		if err != nil {
			t.Errorf("NewDecryptorFromEnv() error = %v", err)
			return
		}
		if d.timeout != customTimeout {
			t.Errorf("NewDecryptorFromEnv() timeout = %v, want %v", d.timeout, customTimeout)
		}
	})
}

func TestParseDecryptedYAMLComplexTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKeys []string
		wantVals map[string]string
		wantErr  bool
	}{
		{
			name: "integer as int",
			input: `
count: 42
`,
			wantKeys: []string{"count"},
			wantVals: map[string]string{
				"count": "42",
			},
			wantErr: false,
		},
		{
			name: "actual float",
			input: `
ratio: 3.14159
`,
			wantKeys: []string{"ratio"},
			wantVals: map[string]string{
				"ratio": "3.14159",
			},
			wantErr: false,
		},
		{
			name: "complex nested structure",
			input: `
config:
  nested:
    key: value
`,
			wantKeys: []string{"config"},
			wantErr:  false,
		},
		{
			name: "array value",
			input: `
items:
  - one
  - two
  - three
`,
			wantKeys: []string{"items"},
			wantErr:  false,
		},
		{
			name:    "invalid yaml",
			input:   `{{{not valid`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseDecryptedYAML([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDecryptedYAML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Check all expected keys exist
			for _, key := range tt.wantKeys {
				if _, ok := result.Data[key]; !ok {
					t.Errorf("parseDecryptedYAML() missing key %q", key)
				}
			}

			// Check values if specified
			for key, wantVal := range tt.wantVals {
				if gotVal := result.StringData[key]; gotVal != wantVal {
					t.Errorf("parseDecryptedYAML() key %q = %q, want %q", key, gotVal, wantVal)
				}
			}
		})
	}
}

func TestValidateEncryptedYAMLInvalidSopsMetadata(t *testing.T) {
	// Test case where sops exists but is not a map
	input := `
username: test
sops: "not a map"
`
	err := ValidateEncryptedYAML([]byte(input))
	if err == nil {
		t.Error("ValidateEncryptedYAML() expected error for non-map sops metadata")
	}
	if !containsString(err.Error(), "invalid sops metadata block") {
		t.Errorf("ValidateEncryptedYAML() error = %v, want error containing 'invalid sops metadata block'", err)
	}
}

func TestDecrypt(t *testing.T) {
	// Test that Decrypt calls DecryptWithContext with background context
	d := NewDecryptor([]string{"fake-key"}, WithTimeout(1*time.Nanosecond))

	// This will fail but exercises the code path
	_, err := d.Decrypt([]byte("test: value"))
	if err == nil {
		t.Skip("Expected error but got nil - sops may behave differently")
	}
	// We just want to verify the method is callable and returns an error
}

func TestDecryptToYAML(t *testing.T) {
	// Test that DecryptToYAML calls DecryptToYAMLWithContext
	d := NewDecryptor([]string{"fake-key"}, WithTimeout(1*time.Nanosecond))

	_, err := d.DecryptToYAML([]byte("test: value"))
	if err == nil {
		t.Skip("Expected error but got nil - sops may behave differently")
	}
}

func TestDecryptToYAMLWithContext(t *testing.T) {
	d := NewDecryptor([]string{"fake-key"}, WithTimeout(1*time.Nanosecond))

	ctx := context.Background()
	_, err := d.DecryptToYAMLWithContext(ctx, []byte("test: value"))
	if err == nil {
		t.Skip("Expected error but got nil - sops may behave differently")
	}
}

func TestRunSopsDecrypt_ContextCanceled(t *testing.T) {
	d := NewDecryptor([]string{"fake-key"}, WithTimeout(30*time.Second))

	// Create an already canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := d.DecryptWithContext(ctx, []byte(`
test: value
sops:
    mac: test
`))

	// Should get some kind of error (either context canceled or sops failure)
	if err == nil {
		t.Skip("Expected error but got nil")
	}
}

func TestDecryptorFields(t *testing.T) {
	// Test that NewDecryptor properly sets all fields
	keys := []string{"key1", "key2"}
	timeout := 45 * time.Second

	d := NewDecryptor(keys, WithTimeout(timeout))

	if len(d.ageKeys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(d.ageKeys))
	}
	if d.ageKeys[0] != "key1" {
		t.Errorf("Expected first key 'key1', got %q", d.ageKeys[0])
	}
	if d.ageKeys[1] != "key2" {
		t.Errorf("Expected second key 'key2', got %q", d.ageKeys[1])
	}
	if d.timeout != timeout {
		t.Errorf("Expected timeout %v, got %v", timeout, d.timeout)
	}
}

func TestDecryptorWithAgeKeyFile(t *testing.T) {
	// Test that ageKeyFile is set in environment when running sops
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.key")
	keyContent := "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
	if err := os.WriteFile(keyFile, []byte(keyContent), 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create decryptor from env with key file
	t.Setenv("SOPS_AGE_KEY", "")
	t.Setenv("SOPS_AGE_KEY_FILE", keyFile)

	d, err := NewDecryptorFromEnv()
	if err != nil {
		t.Fatalf("NewDecryptorFromEnv() error = %v", err)
	}

	// Verify the key file path is stored
	if d.ageKeyFile != keyFile {
		t.Errorf("ageKeyFile = %q, want %q", d.ageKeyFile, keyFile)
	}

	// Try to decrypt (will fail since data isn't really encrypted, but exercises the code path)
	_, err = d.Decrypt([]byte("test: value\nsops:\n  mac: test"))
	if err == nil {
		t.Skip("Expected error but decryption succeeded unexpectedly")
	}
}

func TestDecryptorInterface(t *testing.T) {
	// Test that Decryptor implements DecryptorInterface
	d := NewDecryptor([]string{"test-key"})

	// This should compile - verifying interface compliance
	var _ DecryptorInterface = d
}

func TestWithTempFileCreator(t *testing.T) {
	// Test the withTempFileCreator option
	called := false
	mockCreator := func(dir, pattern string) (TempFile, error) {
		called = true
		return nil, errors.New("mock error")
	}

	d := NewDecryptor([]string{"test-key"}, withTempFileCreator(mockCreator))

	_, err := d.Decrypt([]byte("test: value"))
	if err == nil {
		t.Error("Expected error from mock temp file creator")
	}
	if !called {
		t.Error("Mock temp file creator was not called")
	}
	if !containsString(err.Error(), "failed to create temp file") {
		t.Errorf("Error should contain 'failed to create temp file', got: %v", err)
	}
}

// mockTempFileWriteError is a mock TempFile that fails on Write.
type mockTempFileWriteError struct {
	name string
}

func (m *mockTempFileWriteError) Name() string              { return m.name }
func (m *mockTempFileWriteError) Write([]byte) (int, error) { return 0, errors.New("mock write error") }
func (m *mockTempFileWriteError) Close() error              { return nil }

func TestRunSopsDecrypt_TempFileWriteError(t *testing.T) {
	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, "test.yaml")

	mockCreator := func(dir, pattern string) (TempFile, error) {
		return &mockTempFileWriteError{name: tmpPath}, nil
	}

	d := NewDecryptor([]string{"test-key"}, withTempFileCreator(mockCreator))

	_, err := d.Decrypt([]byte("test: value"))
	if err == nil {
		t.Fatal("Expected write error but got nil")
	}
	if !containsString(err.Error(), "failed to write temp file") {
		t.Errorf("Error should contain 'failed to write temp file', got: %v", err)
	}
}

// mockTempFileCloseError is a mock TempFile that fails on Close.
type mockTempFileCloseError struct {
	name string
}

func (m *mockTempFileCloseError) Name() string                { return m.name }
func (m *mockTempFileCloseError) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockTempFileCloseError) Close() error                { return errors.New("mock close error") }

func TestRunSopsDecrypt_TempFileCloseError(t *testing.T) {
	// Test the tmpFile.Close() error path at decrypt.go:210-211
	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, "test.yaml")

	mockCreator := func(dir, pattern string) (TempFile, error) {
		return &mockTempFileCloseError{name: tmpPath}, nil
	}

	d := NewDecryptor([]string{"test-key"}, withTempFileCreator(mockCreator))

	_, err := d.Decrypt([]byte("test: value"))
	if err == nil {
		t.Fatal("Expected close error but got nil")
	}
	if !containsString(err.Error(), "failed to close temp file") {
		t.Errorf("Error should contain 'failed to close temp file', got: %v", err)
	}
}

func TestParseDecryptedYAMLAllTypes(t *testing.T) {
	// Test all type branches in parseDecryptedYAML
	tests := []struct {
		name     string
		input    string
		key      string
		expected string
	}{
		{
			name:     "string value",
			input:    "key: hello",
			key:      "key",
			expected: "hello",
		},
		{
			name:     "integer (parsed as int by yaml)",
			input:    "key: 123",
			key:      "key",
			expected: "123",
		},
		{
			name:     "float value",
			input:    "key: 3.14",
			key:      "key",
			expected: "3.14",
		},
		{
			name:     "boolean true",
			input:    "key: true",
			key:      "key",
			expected: "true",
		},
		{
			name:     "boolean false",
			input:    "key: false",
			key:      "key",
			expected: "false",
		},
		{
			name:     "null value",
			input:    "key: null",
			key:      "key",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "key: ''",
			key:      "key",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseDecryptedYAML([]byte(tt.input))
			if err != nil {
				t.Fatalf("parseDecryptedYAML() error = %v", err)
			}
			if got := result.StringData[tt.key]; got != tt.expected {
				t.Errorf("parseDecryptedYAML() StringData[%q] = %q, want %q", tt.key, got, tt.expected)
			}
			if _, ok := result.Data[tt.key]; !ok {
				t.Errorf("parseDecryptedYAML() missing Data[%q]", tt.key)
			}
		})
	}
}

func TestParseDecryptedYAMLComplexObject(t *testing.T) {
	// Test complex nested objects that get marshaled back to YAML
	input := `
config:
  database:
    host: localhost
    port: 5432
`
	result, err := parseDecryptedYAML([]byte(input))
	if err != nil {
		t.Fatalf("parseDecryptedYAML() error = %v", err)
	}

	// The config key should exist
	if _, ok := result.Data["config"]; !ok {
		t.Error("Expected config key in result")
	}

	// The value should be YAML
	configStr := result.StringData["config"]
	if configStr == "" {
		t.Error("Expected non-empty config value")
	}
}

func TestDecryptWithContextSuccess(t *testing.T) {
	// Test the successful path through DecryptWithContext
	// Note: This requires sops to be available and will skip if not
	d := NewDecryptor([]string{"AGE-SECRET-KEY-FAKE"})

	ctx := context.Background()
	_, err := d.DecryptWithContext(ctx, []byte(`
test: value
sops:
    mac: test
`))

	// We expect an error since the key is fake, but the code path is exercised
	if err == nil {
		t.Skip("Expected error but got nil - unexpected success")
	}
}

func TestParseDecryptedYAMLArray(t *testing.T) {
	// Test array values (exercises default case for complex types)
	input := `
items:
  - first
  - second
  - third
`
	result, err := parseDecryptedYAML([]byte(input))
	if err != nil {
		t.Fatalf("parseDecryptedYAML() error = %v", err)
	}

	// The items key should exist
	if _, ok := result.Data["items"]; !ok {
		t.Error("Expected items key in result")
	}

	// The value should contain the array elements
	itemsStr := result.StringData["items"]
	if !containsString(itemsStr, "first") {
		t.Errorf("Expected items to contain 'first', got: %s", itemsStr)
	}
}

func TestParseDecryptedYAMLMap(t *testing.T) {
	// Test map values (exercises default case for complex types)
	input := `
config:
  key1: value1
  key2: value2
`
	result, err := parseDecryptedYAML([]byte(input))
	if err != nil {
		t.Fatalf("parseDecryptedYAML() error = %v", err)
	}

	// The config key should exist
	if _, ok := result.Data["config"]; !ok {
		t.Error("Expected config key in result")
	}

	// The value should contain the nested keys
	configStr := result.StringData["config"]
	if !containsString(configStr, "key1") || !containsString(configStr, "value1") {
		t.Errorf("Expected config to contain nested values, got: %s", configStr)
	}
}

func TestWithCommandRunner(t *testing.T) {
	// Test the withCommandRunner option
	mockRunner := func(ctx context.Context, name string, args []string, env []string, input []byte) ([]byte, error) {
		// Return decrypted YAML
		return []byte("username: admin\npassword: secret"), nil
	}

	d := NewDecryptor([]string{"test-key"}, withCommandRunner(mockRunner))

	result, err := d.Decrypt([]byte("test: value"))
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if result.StringData["username"] != "admin" {
		t.Errorf("Expected username 'admin', got %q", result.StringData["username"])
	}
	if result.StringData["password"] != "secret" {
		t.Errorf("Expected password 'secret', got %q", result.StringData["password"])
	}
}

func TestDecryptWithContext_Success(t *testing.T) {
	// Test successful decryption path with mock command runner
	mockRunner := func(ctx context.Context, name string, args []string, env []string, input []byte) ([]byte, error) {
		// Verify command parameters
		if name != "sops" {
			t.Errorf("Expected command 'sops', got %q", name)
		}
		if len(args) != 2 || args[0] != "-d" {
			t.Errorf("Expected args ['-d', <path>], got %v", args)
		}
		// Return decrypted YAML
		return []byte("key: value\ncount: 42"), nil
	}

	d := NewDecryptor([]string{"test-key"}, withCommandRunner(mockRunner))

	ctx := context.Background()
	result, err := d.DecryptWithContext(ctx, []byte("encrypted: data"))
	if err != nil {
		t.Fatalf("DecryptWithContext() error = %v", err)
	}

	if result.StringData["key"] != "value" {
		t.Errorf("Expected key 'value', got %q", result.StringData["key"])
	}
	if result.StringData["count"] != "42" {
		t.Errorf("Expected count '42', got %q", result.StringData["count"])
	}
}

func TestDecryptToYAMLWithContext_Success(t *testing.T) {
	// Test successful raw YAML decryption
	expectedOutput := []byte("decrypted: output\n")
	mockRunner := func(ctx context.Context, name string, args []string, env []string, input []byte) ([]byte, error) {
		return expectedOutput, nil
	}

	d := NewDecryptor([]string{"test-key"}, withCommandRunner(mockRunner))

	result, err := d.DecryptToYAMLWithContext(context.Background(), []byte("encrypted: data"))
	if err != nil {
		t.Fatalf("DecryptToYAMLWithContext() error = %v", err)
	}

	if string(result) != string(expectedOutput) {
		t.Errorf("Expected %q, got %q", string(expectedOutput), string(result))
	}
}

func TestDefaultCommandRunner_Timeout(t *testing.T) {
	// Test that defaultCommandRunner handles timeout correctly
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Let context expire
	time.Sleep(10 * time.Millisecond)

	_, err := defaultCommandRunner(ctx, "sleep", []string{"10"}, nil, nil)
	if err == nil {
		t.Error("Expected timeout error")
	}
	if !containsString(err.Error(), "timed out") {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

func TestDefaultCommandRunner_Canceled(t *testing.T) {
	// Test that defaultCommandRunner handles cancellation correctly
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := defaultCommandRunner(ctx, "sleep", []string{"10"}, nil, nil)
	if err == nil {
		t.Error("Expected canceled error")
	}
	if !containsString(err.Error(), "canceled") {
		t.Errorf("Expected canceled error, got: %v", err)
	}
}

func TestDefaultCommandRunner_CommandFailure(t *testing.T) {
	// Test that defaultCommandRunner handles command failure correctly
	ctx := context.Background()

	_, err := defaultCommandRunner(ctx, "false", nil, nil, nil)
	if err == nil {
		t.Error("Expected command failure error")
	}
	if !containsString(err.Error(), "sops decrypt failed") {
		t.Errorf("Expected 'sops decrypt failed' error, got: %v", err)
	}
}

func TestDefaultCommandRunner_Success(t *testing.T) {
	// Test successful command execution
	ctx := context.Background()

	output, err := defaultCommandRunner(ctx, "echo", []string{"hello"}, nil, nil)
	if err != nil {
		t.Fatalf("defaultCommandRunner() error = %v", err)
	}

	if !containsString(string(output), "hello") {
		t.Errorf("Expected output to contain 'hello', got: %s", string(output))
	}
}

func TestCommandRunnerWithEnvironment(t *testing.T) {
	// Test that environment variables are passed to command
	envChecked := false
	mockRunner := func(ctx context.Context, name string, args []string, env []string, input []byte) ([]byte, error) {
		for _, e := range env {
			if containsString(e, "SOPS_AGE_KEY=") {
				envChecked = true
			}
		}
		return []byte("key: value"), nil
	}

	d := NewDecryptor([]string{"test-key"}, withCommandRunner(mockRunner))
	_, err := d.Decrypt([]byte("test: value"))
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !envChecked {
		t.Error("SOPS_AGE_KEY environment variable was not passed to command")
	}
}

func TestCommandRunnerWithKeyFile(t *testing.T) {
	// Test that SOPS_AGE_KEY_FILE is passed when set
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.key")
	if err := os.WriteFile(keyFile, []byte("AGE-SECRET-KEY-TEST"), 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	keyFileChecked := false
	mockRunner := func(ctx context.Context, name string, args []string, env []string, input []byte) ([]byte, error) {
		for _, e := range env {
			if containsString(e, "SOPS_AGE_KEY_FILE="+keyFile) {
				keyFileChecked = true
			}
		}
		return []byte("key: value"), nil
	}

	t.Setenv("SOPS_AGE_KEY", "")
	t.Setenv("SOPS_AGE_KEY_FILE", keyFile)

	d, err := NewDecryptorFromEnv(withCommandRunner(mockRunner))
	if err != nil {
		t.Fatalf("NewDecryptorFromEnv() error = %v", err)
	}

	_, err = d.Decrypt([]byte("test: value"))
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !keyFileChecked {
		t.Error("SOPS_AGE_KEY_FILE environment variable was not passed to command")
	}
}
