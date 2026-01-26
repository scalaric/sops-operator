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
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestSchemeRegistration(t *testing.T) {
	// Create a new scheme
	scheme := runtime.NewScheme()

	// Add our types to the scheme
	if err := AddToScheme(scheme); err != nil {
		t.Errorf("AddToScheme() error = %v", err)
	}

	// Verify SopsSecret is registered
	gvk := schema.GroupVersionKind{
		Group:   GroupVersion.Group,
		Version: GroupVersion.Version,
		Kind:    "SopsSecret",
	}

	if !scheme.Recognizes(gvk) {
		t.Errorf("Scheme does not recognize SopsSecret GVK: %v", gvk)
	}

	// Verify SopsSecretList is registered
	gvkList := schema.GroupVersionKind{
		Group:   GroupVersion.Group,
		Version: GroupVersion.Version,
		Kind:    "SopsSecretList",
	}

	if !scheme.Recognizes(gvkList) {
		t.Errorf("Scheme does not recognize SopsSecretList GVK: %v", gvkList)
	}
}

func TestGroupVersion(t *testing.T) {
	// Verify group and version constants
	if GroupVersion.Group != "secrets.scalaric.io" {
		t.Errorf("GroupVersion.Group = %q, want %q", GroupVersion.Group, "secrets.scalaric.io")
	}
	if GroupVersion.Version != "v1alpha1" {
		t.Errorf("GroupVersion.Version = %q, want %q", GroupVersion.Version, "v1alpha1")
	}
}

func TestConditionTypeConstants(t *testing.T) {
	// Verify condition type constants are properly defined
	if ConditionTypeReady != "Ready" {
		t.Errorf("ConditionTypeReady = %q, want %q", ConditionTypeReady, "Ready")
	}
	if ConditionTypeDecrypted != "Decrypted" {
		t.Errorf("ConditionTypeDecrypted = %q, want %q", ConditionTypeDecrypted, "Decrypted")
	}
}

func TestSopsSecretSpec(t *testing.T) {
	spec := SopsSecretSpec{
		SopsSecret:        "encrypted-data",
		SecretName:        "my-secret",
		SecretType:        "Opaque",
		SecretLabels:      map[string]string{"key": "value"},
		SecretAnnotations: map[string]string{"annotation": "value"},
		Suspend:           true,
	}

	if spec.SopsSecret != "encrypted-data" {
		t.Errorf("SopsSecret = %q, want %q", spec.SopsSecret, "encrypted-data")
	}
	if spec.SecretName != "my-secret" {
		t.Errorf("SecretName = %q, want %q", spec.SecretName, "my-secret")
	}
	if spec.SecretType != "Opaque" {
		t.Errorf("SecretType = %q, want %q", spec.SecretType, "Opaque")
	}
	if spec.SecretLabels["key"] != "value" {
		t.Errorf("SecretLabels[key] = %q, want %q", spec.SecretLabels["key"], "value")
	}
	if spec.SecretAnnotations["annotation"] != "value" {
		t.Errorf("SecretAnnotations[annotation] = %q, want %q", spec.SecretAnnotations["annotation"], "value")
	}
	if !spec.Suspend {
		t.Error("Suspend = false, want true")
	}
}

func TestSopsSecretStatus(t *testing.T) {
	status := SopsSecretStatus{
		SecretName:         "my-secret",
		LastDecryptedHash:  "abc123",
		ObservedGeneration: 5,
	}

	if status.SecretName != "my-secret" {
		t.Errorf("SecretName = %q, want %q", status.SecretName, "my-secret")
	}
	if status.LastDecryptedHash != "abc123" {
		t.Errorf("LastDecryptedHash = %q, want %q", status.LastDecryptedHash, "abc123")
	}
	if status.ObservedGeneration != 5 {
		t.Errorf("ObservedGeneration = %d, want %d", status.ObservedGeneration, 5)
	}
}

func TestSopsSecret(t *testing.T) {
	sopsSecret := &SopsSecret{
		Spec: SopsSecretSpec{
			SopsSecret: "test-data",
		},
		Status: SopsSecretStatus{
			SecretName: "created-secret",
		},
	}

	if sopsSecret.Spec.SopsSecret != "test-data" {
		t.Errorf("Spec.SopsSecret = %q, want %q", sopsSecret.Spec.SopsSecret, "test-data")
	}
	if sopsSecret.Status.SecretName != "created-secret" {
		t.Errorf("Status.SecretName = %q, want %q", sopsSecret.Status.SecretName, "created-secret")
	}
}

func TestSopsSecretList(t *testing.T) {
	list := &SopsSecretList{
		Items: []SopsSecret{
			{
				Spec: SopsSecretSpec{SopsSecret: "item1"},
			},
			{
				Spec: SopsSecretSpec{SopsSecret: "item2"},
			},
		},
	}

	if len(list.Items) != 2 {
		t.Errorf("Items length = %d, want %d", len(list.Items), 2)
	}
	if list.Items[0].Spec.SopsSecret != "item1" {
		t.Errorf("Items[0].Spec.SopsSecret = %q, want %q", list.Items[0].Spec.SopsSecret, "item1")
	}
	if list.Items[1].Spec.SopsSecret != "item2" {
		t.Errorf("Items[1].Spec.SopsSecret = %q, want %q", list.Items[1].Spec.SopsSecret, "item2")
	}
}
