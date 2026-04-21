package controller

import (
	"testing"

	"github.com/scalaric/sops-operator/pkg/sops"
)

func TestUnwrapYAMLValues(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string][]byte
		wantVals map[string]string
	}{
		{
			name: "unwraps string value (dockerconfigjson)",
			data: map[string][]byte{
				".dockerconfigjson": []byte(`.dockerconfigjson: '{"auths":{"harbor.xae0.com":{"auth":"dGVzdDp0ZXN0"}}}'`),
			},
			wantVals: map[string]string{
				".dockerconfigjson": `{"auths":{"harbor.xae0.com":{"auth":"dGVzdDp0ZXN0"}}}`,
			},
		},
		{
			name: "preserves map values as-is",
			data: map[string][]byte{
				"app": []byte("app:\n  db:\n    host: localhost"),
			},
			wantVals: map[string]string{
				"app": "app:\n  db:\n    host: localhost",
			},
		},
		{
			name: "falls back on invalid yaml",
			data: map[string][]byte{
				"broken": []byte("{{{invalid"),
			},
			wantVals: map[string]string{
				"broken": "{{{invalid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decrypted := &sops.DecryptedData{
				Data:       tt.data,
				StringData: make(map[string]string),
			}
			result := unwrapYAMLValues(decrypted)
			for key, want := range tt.wantVals {
				if got := string(result[key]); got != want {
					t.Errorf("unwrapYAMLValues() key %q = %q, want %q", key, got, want)
				}
			}
		})
	}
}
