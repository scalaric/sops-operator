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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SopsSecretSpec defines the desired state of SopsSecret
type SopsSecretSpec struct {
	// sopsSecret contains the full SOPS-encrypted YAML including MAC and metadata.
	// This is the raw output from `sops -e secret.yaml`.
	// +kubebuilder:validation:Required
	SopsSecret string `json:"sopsSecret"`

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

// SopsSecretStatus defines the observed state of SopsSecret.
type SopsSecretStatus struct {
	// secretName is the name of the created Kubernetes Secret.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// lastDecryptedHash is the hash of the last successfully decrypted sopsSecret.
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

	// ConditionTypeDecrypted indicates the sopsSecret was successfully decrypted.
	ConditionTypeDecrypted = "Decrypted"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Secret",type="string",JSONPath=".status.secretName"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// SopsSecret is the Schema for the sopssecrets API.
// It contains a SOPS-encrypted YAML that will be decrypted and converted to a Kubernetes Secret.
type SopsSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec   SopsSecretSpec   `json:"spec"`
	Status SopsSecretStatus `json:"status,omitempty"`
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
