package sops

import (
	"testing"
)

// FuzzParseDecryptedYAML tests the YAML parsing logic with arbitrary input.
func FuzzParseDecryptedYAML(f *testing.F) {
	// Add seed corpus
	f.Add([]byte("key: value"))
	f.Add([]byte("key: 123"))
	f.Add([]byte("key: true"))
	f.Add([]byte("key: null"))
	f.Add([]byte("key: 3.14"))
	f.Add([]byte("nested:\n  key: value"))
	f.Add([]byte("array:\n  - item1\n  - item2"))
	f.Add([]byte("sops:\n  mac: test\nkey: value"))
	f.Add([]byte(""))
	f.Add([]byte("invalid: yaml: :::"))
	f.Add([]byte("key: \"multi\\nline\""))
	f.Add([]byte("binary: !!binary SGVsbG8gV29ybGQ="))

	f.Fuzz(func(t *testing.T, data []byte) {
		// parseDecryptedYAML should not panic on any input
		_, _ = parseDecryptedYAML(data)
	})
}

// FuzzValidateEncryptedYAML tests the validation logic with arbitrary input.
func FuzzValidateEncryptedYAML(f *testing.F) {
	// Add seed corpus with valid SOPS structures
	f.Add([]byte("sops:\n  mac: abc123\nkey: ENC[AES256_GCM,data:...]"))
	f.Add([]byte("sops:\n  mac: test\n  version: \"3.7.3\"\nkey: value"))
	f.Add([]byte(""))
	f.Add([]byte("no_sops: here"))
	f.Add([]byte("sops: not_a_map"))
	f.Add([]byte("sops:\n  no_mac: here"))
	f.Add([]byte("invalid yaml :::"))
	f.Add([]byte("key: value\nsops:\n  mac: valid"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// ValidateEncryptedYAML should not panic on any input
		_ = ValidateEncryptedYAML(data)
	})
}
