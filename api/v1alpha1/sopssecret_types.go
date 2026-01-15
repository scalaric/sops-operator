/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SopsSecretSpec defines the desired state of SopsSecret
type SopsSecretSpec struct {
	// data contains the secret data. Each key can be a simple value or nested structure.
	// Values matching encrypted_regex in .sops will be encrypted by SOPS.
	// After applying `sops -e -i`, encrypted values will look like: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
	// +kubebuilder:validation:Required
	Data map[string]apiextensionsv1.JSON `json:"data"`

	// secretName is the name of the Kubernetes Secret to create.
	// Defaults to the SopsSecret name if not specified.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// secretType is the type of Secret to create.
	// Defaults to Opaque.
	// +kubebuilder:default=Opaque
	// +optional
	SecretType corev1.SecretType `json:"secretType,omitempty"`

	// secretLabels are additional labels to add to the created Secret.
	// +optional
	SecretLabels map[string]string `json:"secretLabels,omitempty"`

	// secretAnnotations are additional annotations to add to the created Secret.
	// +optional
	SecretAnnotations map[string]string `json:"secretAnnotations,omitempty"`

	// suspend stops reconciliation when true.
	// +optional
	Suspend bool `json:"suspend,omitempty"`
}

// SopsMetadata contains SOPS encryption metadata.
// This is placed at the root level of the CRD by `sops -e`.
type SopsMetadata struct {
	// age contains AGE recipient information
	// +optional
	Age []AgeRecipient `json:"age,omitempty"`

	// kms contains AWS KMS key information
	// +optional
	KMS []KMSKey `json:"kms,omitempty"`

	// gcp_kms contains GCP KMS key information
	// +optional
	GCPKMS []GCPKMSKey `json:"gcp_kms,omitempty"`

	// azure_kv contains Azure Key Vault information
	// +optional
	AzureKV []AzureKVKey `json:"azure_kv,omitempty"`

	// hc_vault contains HashiCorp Vault information
	// +optional
	HCVault []HCVaultKey `json:"hc_vault,omitempty"`

	// mac is the message authentication code
	// +optional
	Mac string `json:"mac,omitempty"`

	// lastmodified is the last modification timestamp
	// +optional
	LastModified string `json:"lastmodified,omitempty"`

	// version is the SOPS version
	// +optional
	Version string `json:"version,omitempty"`

	// encrypted_regex is the regex for fields to encrypt
	// +optional
	EncryptedRegex string `json:"encrypted_regex,omitempty"`

	// encrypted_suffix is the suffix for fields to encrypt
	// +optional
	EncryptedSuffix string `json:"encrypted_suffix,omitempty"`

	// unencrypted_regex is the regex for fields to leave unencrypted
	// +optional
	UnencryptedRegex string `json:"unencrypted_regex,omitempty"`
}

// AgeRecipient contains AGE key recipient information.
type AgeRecipient struct {
	// recipient is the AGE public key
	// +optional
	Recipient string `json:"recipient,omitempty"`
	// enc is the encrypted data key
	// +optional
	Enc string `json:"enc,omitempty"`
}

// KMSKey contains AWS KMS key information.
type KMSKey struct {
	// arn is the AWS KMS key ARN
	// +optional
	ARN string `json:"arn,omitempty"`
	// enc is the encrypted data key
	// +optional
	Enc string `json:"enc,omitempty"`
}

// GCPKMSKey contains GCP KMS key information.
type GCPKMSKey struct {
	// resource_id is the GCP KMS key resource ID
	// +optional
	ResourceID string `json:"resource_id,omitempty"`
	// enc is the encrypted data key
	// +optional
	Enc string `json:"enc,omitempty"`
}

// AzureKVKey contains Azure Key Vault key information.
type AzureKVKey struct {
	// vault_url is the Azure Key Vault URL
	// +optional
	VaultURL string `json:"vault_url,omitempty"`
	// name is the key name
	// +optional
	Name string `json:"name,omitempty"`
	// enc is the encrypted data key
	// +optional
	Enc string `json:"enc,omitempty"`
}

// HCVaultKey contains HashiCorp Vault key information.
type HCVaultKey struct {
	// vault_address is the Vault address
	// +optional
	VaultAddress string `json:"vault_address,omitempty"`
	// engine_path is the path to the transit engine
	// +optional
	EnginePath string `json:"engine_path,omitempty"`
	// key_name is the transit key name
	// +optional
	KeyName string `json:"key_name,omitempty"`
	// enc is the encrypted data key
	// +optional
	Enc string `json:"enc,omitempty"`
}

// SopsSecretStatus defines the observed state of SopsSecret.
type SopsSecretStatus struct {
	// secretName is the name of the created Kubernetes Secret.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// lastDecryptedHash is the hash of the last successfully decrypted data.
	// Used to detect changes and trigger re-decryption.
	// +optional
	LastDecryptedHash string `json:"lastDecryptedHash,omitempty"`

	// lastDecryptedTime is the timestamp of the last successful decryption.
	// +optional
	LastDecryptedTime *metav1.Time `json:"lastDecryptedTime,omitempty"`

	// observedGeneration is the generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the SopsSecret resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

const (
	// ConditionTypeReady indicates the SopsSecret has been successfully decrypted
	// and the Kubernetes Secret has been created/updated.
	ConditionTypeReady = "Ready"

	// ConditionTypeDecrypted indicates the spec.data was successfully decrypted.
	ConditionTypeDecrypted = "Decrypted"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Secret",type="string",JSONPath=".status.secretName"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// SopsSecret is the Schema for the sopssecrets API.
// It contains encrypted data that will be decrypted by SOPS and converted to a Kubernetes Secret.
// The entire CRD can be encrypted using `sops -e -i file.yaml`.
type SopsSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec   SopsSecretSpec   `json:"spec"`
	Status SopsSecretStatus `json:"status,omitempty"`

	// sops contains SOPS metadata added by `sops -e`.
	// This field is at root level to enable direct encryption of the CRD.
	// +optional
	Sops *SopsMetadata `json:"sops,omitempty"`
}

// +kubebuilder:object:root=true

// SopsSecretList contains a list of SopsSecret
type SopsSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SopsSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SopsSecret{}, &SopsSecretList{})
}
