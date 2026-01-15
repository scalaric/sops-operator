package sops

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultDecryptTimeout is the default timeout for sops decrypt operations.
	DefaultDecryptTimeout = 30 * time.Second
)

// Decryptor handles SOPS decryption with AGE keys.
type Decryptor struct {
	ageKeys    []string
	ageKeyFile string
	timeout    time.Duration
}

// Option configures a Decryptor.
type Option func(*Decryptor)

// WithTimeout sets a custom timeout for decrypt operations.
func WithTimeout(d time.Duration) Option {
	return func(dec *Decryptor) {
		dec.timeout = d
	}
}

// NewDecryptor creates a new Decryptor with the given AGE private keys.
func NewDecryptor(ageKeys []string, opts ...Option) *Decryptor {
	d := &Decryptor{
		ageKeys: ageKeys,
		timeout: DefaultDecryptTimeout,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// NewDecryptorFromEnv creates a Decryptor using AGE keys from environment.
// It checks SOPS_AGE_KEY and SOPS_AGE_KEY_FILE environment variables.
func NewDecryptorFromEnv(opts ...Option) (*Decryptor, error) {
	var keys []string

	if key := os.Getenv("SOPS_AGE_KEY"); key != "" {
		keys = append(keys, strings.Split(key, "\n")...)
	}

	keyFile := os.Getenv("SOPS_AGE_KEY_FILE")
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read AGE key file %s: %w", keyFile, err)
		}
		keys = append(keys, strings.Split(string(data), "\n")...)
	}

	// Filter out empty lines and comments
	var validKeys []string
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k != "" && !strings.HasPrefix(k, "#") {
			validKeys = append(validKeys, k)
		}
	}

	if len(validKeys) == 0 {
		return nil, fmt.Errorf("no AGE keys found in SOPS_AGE_KEY or SOPS_AGE_KEY_FILE")
	}

	d := &Decryptor{
		ageKeys:    validKeys,
		ageKeyFile: keyFile,
		timeout:    DefaultDecryptTimeout,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d, nil
}

// DecryptedData represents the decrypted secret data.
type DecryptedData struct {
	// Data contains the decrypted key-value pairs as bytes.
	Data map[string][]byte
	// StringData contains string values (for convenience).
	StringData map[string]string
}

// Decrypt decrypts a SOPS-encrypted YAML and returns the data.
// The input should be the full SOPS YAML including sops metadata block.
// Deprecated: Use DecryptCRD for the new CRD format with spec.data.
func (d *Decryptor) Decrypt(encryptedYAML []byte) (*DecryptedData, error) {
	return d.DecryptWithContext(context.Background(), encryptedYAML)
}

// DecryptWithContext decrypts with a custom context for cancellation.
// Deprecated: Use DecryptCRDWithContext for the new CRD format with spec.data.
func (d *Decryptor) DecryptWithContext(ctx context.Context, encryptedYAML []byte) (*DecryptedData, error) {
	decrypted, err := d.runSopsDecrypt(ctx, encryptedYAML)
	if err != nil {
		return nil, err
	}
	return parseDecryptedYAML(decrypted)
}

// DecryptCRD decrypts a SopsSecret CRD and extracts the spec.data field.
// The input should be the serialized CRD with spec.data and sops metadata.
func (d *Decryptor) DecryptCRD(encryptedYAML []byte) (*DecryptedData, error) {
	return d.DecryptCRDWithContext(context.Background(), encryptedYAML)
}

// DecryptCRDWithContext decrypts a CRD with a custom context for cancellation.
func (d *Decryptor) DecryptCRDWithContext(ctx context.Context, encryptedYAML []byte) (*DecryptedData, error) {
	decrypted, err := d.runSopsDecrypt(ctx, encryptedYAML)
	if err != nil {
		return nil, err
	}
	return parseCRDDecryptedYAML(decrypted)
}

// DecryptToYAML decrypts and returns raw YAML bytes.
func (d *Decryptor) DecryptToYAML(encryptedYAML []byte) ([]byte, error) {
	return d.DecryptToYAMLWithContext(context.Background(), encryptedYAML)
}

// DecryptToYAMLWithContext decrypts with a custom context.
func (d *Decryptor) DecryptToYAMLWithContext(ctx context.Context, encryptedYAML []byte) ([]byte, error) {
	return d.runSopsDecrypt(ctx, encryptedYAML)
}

func (d *Decryptor) runSopsDecrypt(ctx context.Context, encryptedYAML []byte) ([]byte, error) {
	// Create temp file for encrypted data
	tmpFile, err := os.CreateTemp("", "sops-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(encryptedYAML); err != nil {
		return nil, fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	// Create context with timeout
	execCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	// Set up environment for sops
	env := os.Environ()
	if len(d.ageKeys) > 0 {
		env = append(env, "SOPS_AGE_KEY="+strings.Join(d.ageKeys, "\n"))
	}
	if d.ageKeyFile != "" {
		env = append(env, "SOPS_AGE_KEY_FILE="+d.ageKeyFile)
	}

	// Run sops decrypt with context
	cmd := exec.CommandContext(execCtx, "sops", "-d", tmpPath)
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if execCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("sops decrypt timed out after %v", d.timeout)
		}
		if execCtx.Err() == context.Canceled {
			return nil, fmt.Errorf("sops decrypt was canceled")
		}
		return nil, fmt.Errorf("sops decrypt failed: %w: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// parseCRDDecryptedYAML parses the decrypted CRD YAML and extracts spec.data.
func parseCRDDecryptedYAML(data []byte) (*DecryptedData, error) {
	var raw map[string]interface{}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted YAML: %w", err)
	}

	// Extract spec.data
	spec, ok := raw["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'spec' field in decrypted YAML")
	}

	dataField, ok := spec["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'spec.data' field in decrypted YAML")
	}

	return convertToDecryptedData(dataField)
}

// parseDecryptedYAML parses flat decrypted YAML (legacy format).
func parseDecryptedYAML(data []byte) (*DecryptedData, error) {
	var raw map[string]interface{}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted YAML: %w", err)
	}

	// Remove sops metadata if present
	delete(raw, "sops")

	return convertToDecryptedData(raw)
}

// convertToDecryptedData converts a map to DecryptedData.
func convertToDecryptedData(raw map[string]interface{}) (*DecryptedData, error) {
	result := &DecryptedData{
		Data:       make(map[string][]byte),
		StringData: make(map[string]string),
	}

	for key, value := range raw {
		switch v := value.(type) {
		case string:
			result.Data[key] = []byte(v)
			result.StringData[key] = v
		case []byte:
			result.Data[key] = v
			result.StringData[key] = string(v)
		case int:
			str := fmt.Sprintf("%d", v)
			result.Data[key] = []byte(str)
			result.StringData[key] = str
		case int64:
			str := fmt.Sprintf("%d", v)
			result.Data[key] = []byte(str)
			result.StringData[key] = str
		case float64:
			// Check if it's actually an integer
			if v == float64(int64(v)) {
				str := fmt.Sprintf("%d", int64(v))
				result.Data[key] = []byte(str)
				result.StringData[key] = str
			} else {
				str := fmt.Sprintf("%g", v)
				result.Data[key] = []byte(str)
				result.StringData[key] = str
			}
		case bool:
			str := fmt.Sprintf("%t", v)
			result.Data[key] = []byte(str)
			result.StringData[key] = str
		case nil:
			result.Data[key] = []byte("")
			result.StringData[key] = ""
		default:
			// For complex types, marshal back to YAML
			yamlBytes, err := yaml.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal value for key %s: %w", key, err)
			}
			// Remove trailing newline from yaml.Marshal
			yamlBytes = bytes.TrimSuffix(yamlBytes, []byte("\n"))
			result.Data[key] = yamlBytes
			result.StringData[key] = string(yamlBytes)
		}
	}

	return result, nil
}

// ValidateEncryptedYAML checks if the given data is a valid SOPS-encrypted YAML.
// Works with both legacy format (sops at root) and CRD format (spec.data + sops at root).
func ValidateEncryptedYAML(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty YAML data")
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}

	sopsMetadata, ok := raw["sops"]
	if !ok {
		return fmt.Errorf("missing sops metadata block")
	}

	sopsMap, ok := sopsMetadata.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid sops metadata block")
	}

	if _, ok := sopsMap["mac"]; !ok {
		return fmt.Errorf("missing MAC in sops metadata")
	}

	return nil
}
