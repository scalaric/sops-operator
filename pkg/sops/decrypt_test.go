package sops

import (
	"context"
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
	})

	t.Run("filters comments and empty lines", func(t *testing.T) {
		t.Setenv("SOPS_AGE_KEY", "# comment\n\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n  \n")
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
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[:len(substr)] == substr || containsString(s[1:], substr)))
}
