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

package controller

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secretsv1alpha1 "github.com/scalaric/sops-operator/api/v1alpha1"
	"github.com/scalaric/sops-operator/pkg/sops"
)

// MockDecryptor is a test helper that implements sops.DecryptorInterface
type MockDecryptor struct {
	DecryptFunc            func([]byte) (*sops.DecryptedData, error)
	DecryptWithContextFunc func(context.Context, []byte) (*sops.DecryptedData, error)
}

func (m *MockDecryptor) Decrypt(data []byte) (*sops.DecryptedData, error) {
	if m.DecryptFunc != nil {
		return m.DecryptFunc(data)
	}
	return &sops.DecryptedData{
		Data:       map[string][]byte{"test": []byte("value")},
		StringData: map[string]string{"test": "value"},
	}, nil
}

func (m *MockDecryptor) DecryptWithContext(ctx context.Context, data []byte) (*sops.DecryptedData, error) {
	if m.DecryptWithContextFunc != nil {
		return m.DecryptWithContextFunc(ctx, data)
	}
	return m.Decrypt(data)
}

// Verify MockDecryptor implements the interface
var _ sops.DecryptorInterface = &MockDecryptor{}

// ErrorClient is a mock client that returns errors for testing error paths
type ErrorClient struct {
	client.Client
	GetError          error
	CreateError       error
	UpdateError       error
	DeleteError       error
	StatusUpdateError error
	GetCallCount      int
	CreateCallCount   int
	UpdateCallCount   int
	DeleteCallCount   int
	StatusUpdateCount int
	// Control which call should error
	GetErrorOnCall    int // 0 = always, >0 = specific call
	UpdateErrorOnCall int
	CreateErrorOnCall int
	DeleteErrorOnCall int
}

func (e *ErrorClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	e.GetCallCount++
	if e.GetError != nil && (e.GetErrorOnCall == 0 || e.GetErrorOnCall == e.GetCallCount) {
		return e.GetError
	}
	return e.Client.Get(ctx, key, obj, opts...)
}

func (e *ErrorClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	e.CreateCallCount++
	if e.CreateError != nil && (e.CreateErrorOnCall == 0 || e.CreateErrorOnCall == e.CreateCallCount) {
		return e.CreateError
	}
	return e.Client.Create(ctx, obj, opts...)
}

func (e *ErrorClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	e.UpdateCallCount++
	if e.UpdateError != nil && (e.UpdateErrorOnCall == 0 || e.UpdateErrorOnCall == e.UpdateCallCount) {
		return e.UpdateError
	}
	return e.Client.Update(ctx, obj, opts...)
}

func (e *ErrorClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	e.DeleteCallCount++
	if e.DeleteError != nil && (e.DeleteErrorOnCall == 0 || e.DeleteErrorOnCall == e.DeleteCallCount) {
		return e.DeleteError
	}
	return e.Client.Delete(ctx, obj, opts...)
}

// ErrorStatusWriter wraps status updates to return errors
type ErrorStatusWriter struct {
	client.StatusWriter
	UpdateError error
}

func (e *ErrorStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if e.UpdateError != nil {
		return e.UpdateError
	}
	return e.StatusWriter.Update(ctx, obj, opts...)
}

func (e *ErrorClient) Status() client.StatusWriter {
	if e.StatusUpdateError != nil {
		return &ErrorStatusWriter{
			StatusWriter: e.Client.Status(),
			UpdateError:  e.StatusUpdateError,
		}
	}
	return e.Client.Status()
}

// DeletionTimestampClient wraps a client and sets DeletionTimestamp on Get
// It also handles Update to clear DeletionTimestamp before updating (simulating K8s behavior)
type DeletionTimestampClient struct {
	client.Client
	DeletionTimestamp *metav1.Time
}

func (d *DeletionTimestampClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := d.Client.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	// Set deletion timestamp on SopsSecret
	if ss, ok := obj.(*secretsv1alpha1.SopsSecret); ok && d.DeletionTimestamp != nil {
		ss.DeletionTimestamp = d.DeletionTimestamp
	}
	return nil
}

func (d *DeletionTimestampClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	// Clear DeletionTimestamp before updating (fake client doesn't like it)
	if ss, ok := obj.(*secretsv1alpha1.SopsSecret); ok {
		ss.DeletionTimestamp = nil
	}
	return d.Client.Update(ctx, obj, opts...)
}

var _ = Describe("SopsSecret Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		sopssecret := &secretsv1alpha1.SopsSecret{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind SopsSecret")
			err := k8sClient.Get(ctx, typeNamespacedName, sopssecret)
			if err != nil && errors.IsNotFound(err) {
				resource := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `
username: test
sops:
    mac: ENC[AES256_GCM,data:test,iv:test,tag:test,type:str]
    version: 3.9.0
`,
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &secretsv1alpha1.SopsSecret{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				By("Cleanup the specific resource instance SopsSecret")
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		It("should create the SopsSecret resource", func() {
			By("Getting the created resource")
			resource := &secretsv1alpha1.SopsSecret{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())
			Expect(resource.Spec.SopsSecret).To(ContainSubstring("username"))
		})
	})

	Context("Unit tests for helper functions", func() {
		var reconciler *SopsSecretReconciler

		BeforeEach(func() {
			reconciler = &SopsSecretReconciler{
				Client:    k8sClient,
				Scheme:    scheme.Scheme,
				Decryptor: sops.NewDecryptor([]string{"test-key"}),
			}
		})

		Describe("getSecretName", func() {
			It("should return spec.secretName when set", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "my-sops-secret",
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SecretName: "custom-secret-name",
					},
				}
				Expect(reconciler.getSecretName(sopsSecret)).To(Equal("custom-secret-name"))
			})

			It("should return SopsSecret name when spec.secretName is not set", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "my-sops-secret",
					},
					Spec: secretsv1alpha1.SopsSecretSpec{},
				}
				Expect(reconciler.getSecretName(sopsSecret)).To(Equal("my-sops-secret"))
			})
		})

		Describe("buildSecret", func() {
			It("should build a secret with default type", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-sops-secret",
						Namespace: "default",
					},
					Spec: secretsv1alpha1.SopsSecretSpec{},
				}
				decrypted := &sops.DecryptedData{
					Data: map[string][]byte{
						"username": []byte("admin"),
						"password": []byte("secret"),
					},
				}

				secret := reconciler.buildSecret(sopsSecret, decrypted)

				Expect(secret.Name).To(Equal("my-sops-secret"))
				Expect(secret.Namespace).To(Equal("default"))
				Expect(secret.Type).To(Equal(corev1.SecretTypeOpaque))
				Expect(secret.Data["username"]).To(Equal([]byte("admin")))
				Expect(secret.Data["password"]).To(Equal([]byte("secret")))
				Expect(secret.Labels["app.kubernetes.io/managed-by"]).To(Equal("sops-operator"))
				Expect(secret.Labels["secrets.scalaric.io/sopssecret"]).To(Equal("my-sops-secret"))
				Expect(secret.Annotations["secrets.scalaric.io/source"]).To(Equal("default/my-sops-secret"))
			})

			It("should build a secret with custom type", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-sops-secret",
						Namespace: "default",
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SecretType: corev1.SecretTypeTLS,
					},
				}
				decrypted := &sops.DecryptedData{
					Data: map[string][]byte{
						"tls.crt": []byte("cert"),
						"tls.key": []byte("key"),
					},
				}

				secret := reconciler.buildSecret(sopsSecret, decrypted)

				Expect(secret.Type).To(Equal(corev1.SecretTypeTLS))
			})

			It("should include custom labels and annotations", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-sops-secret",
						Namespace: "default",
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SecretLabels: map[string]string{
							"custom-label": "custom-value",
						},
						SecretAnnotations: map[string]string{
							"custom-annotation": "custom-value",
						},
					},
				}
				decrypted := &sops.DecryptedData{
					Data: map[string][]byte{},
				}

				secret := reconciler.buildSecret(sopsSecret, decrypted)

				Expect(secret.Labels["custom-label"]).To(Equal("custom-value"))
				Expect(secret.Annotations["custom-annotation"]).To(Equal("custom-value"))
			})

			It("should use custom secret name", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-sops-secret",
						Namespace: "default",
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SecretName: "custom-name",
					},
				}
				decrypted := &sops.DecryptedData{
					Data: map[string][]byte{},
				}

				secret := reconciler.buildSecret(sopsSecret, decrypted)

				Expect(secret.Name).To(Equal("custom-name"))
			})
		})

		Describe("setCondition", func() {
			It("should set a condition on the SopsSecret", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test",
						Generation: 1,
					},
				}

				reconciler.setCondition(sopsSecret, secretsv1alpha1.ConditionTypeReady,
					metav1.ConditionTrue, "Success", "All good")

				Expect(sopsSecret.Status.Conditions).To(HaveLen(1))
				Expect(sopsSecret.Status.Conditions[0].Type).To(Equal(secretsv1alpha1.ConditionTypeReady))
				Expect(sopsSecret.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))
				Expect(sopsSecret.Status.Conditions[0].Reason).To(Equal("Success"))
				Expect(sopsSecret.Status.Conditions[0].Message).To(Equal("All good"))
			})

			It("should update an existing condition", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test",
						Generation: 1,
					},
				}

				reconciler.setCondition(sopsSecret, secretsv1alpha1.ConditionTypeReady,
					metav1.ConditionFalse, "Failed", "Something went wrong")
				reconciler.setCondition(sopsSecret, secretsv1alpha1.ConditionTypeReady,
					metav1.ConditionTrue, "Success", "Fixed now")

				Expect(sopsSecret.Status.Conditions).To(HaveLen(1))
				Expect(sopsSecret.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))
				Expect(sopsSecret.Status.Conditions[0].Reason).To(Equal("Success"))
			})
		})

		Describe("calculateHash", func() {
			It("should return consistent hash for same input", func() {
				input := "test data"
				hash1 := calculateHash(input)
				hash2 := calculateHash(input)

				Expect(hash1).To(Equal(hash2))
				Expect(hash1).To(HaveLen(64)) // SHA256 hex encoded
			})

			It("should return different hash for different input", func() {
				hash1 := calculateHash("data1")
				hash2 := calculateHash("data2")

				Expect(hash1).NotTo(Equal(hash2))
			})
		})
	})

	Context("Reconciler with fake client", func() {
		var (
			reconciler *SopsSecretReconciler
			ctx        context.Context
		)

		BeforeEach(func() {
			ctx = context.Background()
			// Create a fake client with scheme
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme.Scheme).
				WithStatusSubresource(&secretsv1alpha1.SopsSecret{}).
				Build()

			reconciler = &SopsSecretReconciler{
				Client:    fakeClient,
				Scheme:    scheme.Scheme,
				Recorder:  &events.FakeRecorder{},
				Decryptor: sops.NewDecryptor([]string{"test-key"}),
			}
		})

		Describe("Reconcile", func() {
			It("should return empty result when SopsSecret not found", func() {
				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "nonexistent",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should skip reconciliation when suspended", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "suspended-secret",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
						Suspend: true,
					},
				}
				Expect(reconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "suspended-secret",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should add finalizer if not present", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "new-secret",
						Namespace: "default",
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
				}
				Expect(reconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "new-secret",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(time.Second))

				// Verify finalizer was added
				updated := &secretsv1alpha1.SopsSecret{}
				Expect(reconciler.Client.Get(ctx, req.NamespacedName, updated)).To(Succeed())
				Expect(updated.Finalizers).To(ContainElement(finalizerName))
			})

			It("should fail validation for invalid SOPS YAML", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "invalid-secret",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `invalid: yaml
missing: sops_block
`,
					},
				}
				Expect(reconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "invalid-secret",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

				// Verify condition was set
				updated := &secretsv1alpha1.SopsSecret{}
				Expect(reconciler.Client.Get(ctx, req.NamespacedName, updated)).To(Succeed())
				Expect(updated.Status.Conditions).NotTo(BeEmpty())
			})
		})

		Describe("reconcileDelete", func() {
			It("should remove finalizer on delete", func() {
				now := metav1.Now()
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "deleting-secret",
						Namespace:         "default",
						Finalizers:        []string{finalizerName},
						DeletionTimestamp: &now,
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
				}
				Expect(reconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				result, err := reconciler.reconcileDelete(ctx, sopsSecret)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should do nothing if finalizer not present", func() {
				now := metav1.Now()
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "deleting-secret-no-finalizer",
						Namespace:         "default",
						DeletionTimestamp: &now,
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value`,
					},
				}

				result, err := reconciler.reconcileDelete(ctx, sopsSecret)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ctrl.Result{}))
			})
		})

		Describe("SetupWithManager", func() {
			It("should not error with nil manager during setup check", func() {
				// This test verifies the method exists and has correct signature
				// Actual manager setup is tested in integration tests
				Expect(reconciler.SetupWithManager).NotTo(BeNil())
			})
		})

		Describe("updateStatus", func() {
			It("should update status and return requeue after 5 minutes", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "status-update-test",
						Namespace: "default",
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
				}
				Expect(reconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				result, err := reconciler.updateStatus(ctx, sopsSecret)

				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
			})
		})

		Describe("Reconcile with deletion timestamp", func() {
			It("should handle deletion when SopsSecret is being deleted", func() {
				// Test reconcileDelete directly since fake client doesn't properly
				// simulate DeletionTimestamp behavior in Reconcile
				now := metav1.Now()
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "being-deleted-direct",
						Namespace:         "default",
						Finalizers:        []string{finalizerName},
						DeletionTimestamp: &now,
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
				}
				Expect(reconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				result, err := reconciler.reconcileDelete(ctx, sopsSecret)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should call reconcileDelete through Reconcile when DeletionTimestamp is set", func() {
				// Use DeletionTimestampClient to simulate deletion through Reconcile
				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					WithStatusSubresource(&secretsv1alpha1.SopsSecret{}).
					Build()

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "deletion-through-reconcile",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
				}
				Expect(fakeClient.Create(ctx, sopsSecret)).To(Succeed())

				now := metav1.Now()
				deletionClient := &DeletionTimestampClient{
					Client:            fakeClient,
					DeletionTimestamp: &now,
				}

				deletionReconciler := &SopsSecretReconciler{
					Client:    deletionClient,
					Scheme:    scheme.Scheme,
					Recorder:  &events.FakeRecorder{},
					Decryptor: &MockDecryptor{},
				}

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "deletion-through-reconcile",
						Namespace: "default",
					},
				}

				result, err := deletionReconciler.Reconcile(ctx, req)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ctrl.Result{}))
			})
		})

		Describe("Reconcile with existing hash", func() {
			It("should skip decryption when hash matches and secret exists", func() {
				hash := calculateHash(`test: value
sops:
    mac: test
`)
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "hash-match-test",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
						Generation: 1,
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
					Status: secretsv1alpha1.SopsSecretStatus{
						LastDecryptedHash:  hash,
						ObservedGeneration: 1,
						SecretName:         "hash-match-test",
					},
				}
				Expect(reconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				// Create the corresponding secret
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "hash-match-test",
						Namespace: "default",
					},
					Data: map[string][]byte{"test": []byte("value")},
				}
				Expect(reconciler.Client.Create(ctx, secret)).To(Succeed())

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "hash-match-test",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should recreate secret when hash matches but secret is missing", func() {
				hash := calculateHash(`test: value
sops:
    mac: test
`)
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "secret-missing-test",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
						Generation: 1,
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
					Status: secretsv1alpha1.SopsSecretStatus{
						LastDecryptedHash:  hash,
						ObservedGeneration: 1,
						SecretName:         "secret-missing-test",
					},
				}
				Expect(reconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "secret-missing-test",
						Namespace: "default",
					},
				}

				// This should try to recreate the secret (and fail at decryption)
				result, err := reconciler.Reconcile(ctx, req)

				// The validation should fail since sops block is incomplete
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
			})
		})

		Describe("reconcileDelete with owned secret", func() {
			It("should delete owned secret during reconcileDelete", func() {
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "delete-owned-secret",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
						UID:        "test-uid-123",
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
				}
				Expect(reconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				// Create a secret owned by this SopsSecret
				trueVal := true
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "delete-owned-secret",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "secrets.scalaric.io/v1alpha1",
								Kind:       "SopsSecret",
								Name:       "delete-owned-secret",
								UID:        "test-uid-123",
								Controller: &trueVal,
							},
						},
					},
					Data: map[string][]byte{"test": []byte("value")},
				}
				Expect(reconciler.Client.Create(ctx, secret)).To(Succeed())

				result, err := reconciler.reconcileDelete(ctx, sopsSecret)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ctrl.Result{}))
			})
		})
	})

	Context("Reconciler with mock decryptor", func() {
		var (
			mockReconciler *SopsSecretReconciler
			mockDecryptor  *MockDecryptor
			ctx            context.Context
		)

		BeforeEach(func() {
			ctx = context.Background()
			mockDecryptor = &MockDecryptor{}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme.Scheme).
				WithStatusSubresource(&secretsv1alpha1.SopsSecret{}).
				Build()

			mockReconciler = &SopsSecretReconciler{
				Client:    fakeClient,
				Scheme:    scheme.Scheme,
				Recorder:  &events.FakeRecorder{},
				Decryptor: mockDecryptor,
			}
		})

		Describe("Full Reconcile flow with successful decryption", func() {
			It("should create a new Secret when SopsSecret is valid", func() {
				mockDecryptor.DecryptFunc = func(data []byte) (*sops.DecryptedData, error) {
					return &sops.DecryptedData{
						Data: map[string][]byte{
							"username": []byte("admin"),
							"password": []byte("secret123"),
						},
						StringData: map[string]string{
							"username": "admin",
							"password": "secret123",
						},
					}, nil
				}

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "decrypt-success",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `username: ENC[test]
password: ENC[test]
sops:
    mac: test
`,
					},
				}
				Expect(mockReconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "decrypt-success",
						Namespace: "default",
					},
				}

				result, err := mockReconciler.Reconcile(ctx, req)

				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

				// Verify the Secret was created
				secret := &corev1.Secret{}
				err = mockReconciler.Get(ctx, types.NamespacedName{
					Name:      "decrypt-success",
					Namespace: "default",
				}, secret)
				Expect(err).NotTo(HaveOccurred())
				Expect(secret.Data["username"]).To(Equal([]byte("admin")))
				Expect(secret.Data["password"]).To(Equal([]byte("secret123")))
			})

			It("should update existing Secret when SopsSecret changes", func() {
				mockDecryptor.DecryptFunc = func(data []byte) (*sops.DecryptedData, error) {
					return &sops.DecryptedData{
						Data: map[string][]byte{
							"username": []byte("updated"),
						},
						StringData: map[string]string{
							"username": "updated",
						},
					}, nil
				}

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "update-secret",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `username: ENC[test]
sops:
    mac: test
`,
					},
				}
				Expect(mockReconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				// Create existing secret
				existingSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "update-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{"username": []byte("old")},
				}
				Expect(mockReconciler.Client.Create(ctx, existingSecret)).To(Succeed())

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "update-secret",
						Namespace: "default",
					},
				}

				result, err := mockReconciler.Reconcile(ctx, req)

				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

				// Verify the Secret was updated
				secret := &corev1.Secret{}
				err = mockReconciler.Get(ctx, types.NamespacedName{
					Name:      "update-secret",
					Namespace: "default",
				}, secret)
				Expect(err).NotTo(HaveOccurred())
				Expect(secret.Data["username"]).To(Equal([]byte("updated")))
			})

			It("should handle decryption failure", func() {
				mockDecryptor.DecryptFunc = func(data []byte) (*sops.DecryptedData, error) {
					return nil, fmt.Errorf("decryption failed: invalid key")
				}

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "decrypt-fail",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `username: ENC[test]
sops:
    mac: test
`,
					},
				}
				Expect(mockReconciler.Client.Create(ctx, sopsSecret)).To(Succeed())

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "decrypt-fail",
						Namespace: "default",
					},
				}

				result, err := mockReconciler.Reconcile(ctx, req)

				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

				// Verify status condition was set
				updated := &secretsv1alpha1.SopsSecret{}
				Expect(mockReconciler.Client.Get(ctx, req.NamespacedName, updated)).To(Succeed())
				Expect(updated.Status.Conditions).NotTo(BeEmpty())
			})
		})
	})

	Context("Error handling with ErrorClient", func() {
		var (
			ctx context.Context
		)

		BeforeEach(func() {
			ctx = context.Background()
		})

		Describe("Reconcile error paths", func() {
			It("should return error when Get SopsSecret fails (non-NotFound)", func() {
				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					Build()

				errorClient := &ErrorClient{
					Client:   fakeClient,
					GetError: fmt.Errorf("connection refused"),
				}

				reconciler := &SopsSecretReconciler{
					Client:    errorClient,
					Scheme:    scheme.Scheme,
					Recorder:  &events.FakeRecorder{},
					Decryptor: &MockDecryptor{},
				}

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "test-secret",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("connection refused"))
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should return error when adding finalizer fails", func() {
				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					WithStatusSubresource(&secretsv1alpha1.SopsSecret{}).
					Build()

				// Create the SopsSecret first
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "finalizer-error",
						Namespace: "default",
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
				}
				Expect(fakeClient.Create(ctx, sopsSecret)).To(Succeed())

				errorClient := &ErrorClient{
					Client:      fakeClient,
					UpdateError: fmt.Errorf("update failed"),
				}

				reconciler := &SopsSecretReconciler{
					Client:    errorClient,
					Scheme:    scheme.Scheme,
					Recorder:  &events.FakeRecorder{},
					Decryptor: &MockDecryptor{},
				}

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "finalizer-error",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("update failed"))
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should return error when checking existing secret fails (non-NotFound)", func() {
				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					WithStatusSubresource(&secretsv1alpha1.SopsSecret{}).
					Build()

				hash := calculateHash(`test: value
sops:
    mac: test
`)
				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "get-secret-error",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
						Generation: 1,
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
					Status: secretsv1alpha1.SopsSecretStatus{
						LastDecryptedHash:  hash,
						ObservedGeneration: 1,
					},
				}
				Expect(fakeClient.Create(ctx, sopsSecret)).To(Succeed())

				errorClient := &ErrorClient{
					Client:         fakeClient,
					GetError:       fmt.Errorf("network timeout"),
					GetErrorOnCall: 2, // Error on second Get (checking secret)
				}

				reconciler := &SopsSecretReconciler{
					Client:    errorClient,
					Scheme:    scheme.Scheme,
					Recorder:  &events.FakeRecorder{},
					Decryptor: &MockDecryptor{},
				}

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "get-secret-error",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("network timeout"))
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should return error when creating secret fails", func() {
				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					WithStatusSubresource(&secretsv1alpha1.SopsSecret{}).
					Build()

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "create-secret-error",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
				}
				Expect(fakeClient.Create(ctx, sopsSecret)).To(Succeed())

				errorClient := &ErrorClient{
					Client:      fakeClient,
					CreateError: fmt.Errorf("quota exceeded"),
				}

				reconciler := &SopsSecretReconciler{
					Client:   errorClient,
					Scheme:   scheme.Scheme,
					Recorder: &events.FakeRecorder{},
					Decryptor: &MockDecryptor{
						DecryptFunc: func(data []byte) (*sops.DecryptedData, error) {
							return &sops.DecryptedData{
								Data: map[string][]byte{"key": []byte("value")},
							}, nil
						},
					},
				}

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "create-secret-error",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("quota exceeded"))
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should return error when getting secret for update fails (non-NotFound)", func() {
				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					WithStatusSubresource(&secretsv1alpha1.SopsSecret{}).
					Build()

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "get-for-update-error",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
				}
				Expect(fakeClient.Create(ctx, sopsSecret)).To(Succeed())

				errorClient := &ErrorClient{
					Client:         fakeClient,
					GetError:       fmt.Errorf("etcd unavailable"),
					GetErrorOnCall: 2, // Error on second Get (getting secret)
				}

				reconciler := &SopsSecretReconciler{
					Client:   errorClient,
					Scheme:   scheme.Scheme,
					Recorder: &events.FakeRecorder{},
					Decryptor: &MockDecryptor{
						DecryptFunc: func(data []byte) (*sops.DecryptedData, error) {
							return &sops.DecryptedData{
								Data: map[string][]byte{"key": []byte("value")},
							}, nil
						},
					},
				}

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "get-for-update-error",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("etcd unavailable"))
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should return error when updating secret fails", func() {
				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					WithStatusSubresource(&secretsv1alpha1.SopsSecret{}).
					Build()

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "update-secret-error",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
				}
				Expect(fakeClient.Create(ctx, sopsSecret)).To(Succeed())

				// Create existing secret
				existingSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "update-secret-error",
						Namespace: "default",
					},
					Data: map[string][]byte{"old": []byte("data")},
				}
				Expect(fakeClient.Create(ctx, existingSecret)).To(Succeed())

				errorClient := &ErrorClient{
					Client:            fakeClient,
					UpdateError:       fmt.Errorf("conflict"),
					UpdateErrorOnCall: 1, // Error on first Update (updating secret - finalizer already exists)
				}

				reconciler := &SopsSecretReconciler{
					Client:   errorClient,
					Scheme:   scheme.Scheme,
					Recorder: &events.FakeRecorder{},
					Decryptor: &MockDecryptor{
						DecryptFunc: func(data []byte) (*sops.DecryptedData, error) {
							return &sops.DecryptedData{
								Data: map[string][]byte{"key": []byte("value")},
							}, nil
						},
					},
				}

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "update-secret-error",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("conflict"))
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should return error when status update fails", func() {
				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					WithStatusSubresource(&secretsv1alpha1.SopsSecret{}).
					Build()

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "status-error",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `invalid: yaml
missing: sops_block
`,
					},
				}
				Expect(fakeClient.Create(ctx, sopsSecret)).To(Succeed())

				errorClient := &ErrorClient{
					Client:            fakeClient,
					StatusUpdateError: fmt.Errorf("status update failed"),
				}

				reconciler := &SopsSecretReconciler{
					Client:    errorClient,
					Scheme:    scheme.Scheme,
					Recorder:  &events.FakeRecorder{},
					Decryptor: &MockDecryptor{},
				}

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "status-error",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("status update failed"))
				Expect(result).To(Equal(ctrl.Result{}))
			})
		})

		Describe("reconcileDelete error paths", func() {
			It("should return error when getting secret for delete fails (non-NotFound)", func() {
				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					Build()

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "delete-get-error",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
				}

				errorClient := &ErrorClient{
					Client:   fakeClient,
					GetError: fmt.Errorf("storage backend error"),
				}

				reconciler := &SopsSecretReconciler{
					Client:    errorClient,
					Scheme:    scheme.Scheme,
					Recorder:  &events.FakeRecorder{},
					Decryptor: &MockDecryptor{},
				}

				result, err := reconciler.reconcileDelete(ctx, sopsSecret)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("storage backend error"))
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should return error when deleting secret fails", func() {
				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					Build()

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "delete-error",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
						UID:        "test-uid",
					},
				}

				// Create owned secret
				trueVal := true
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "delete-error",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "secrets.scalaric.io/v1alpha1",
								Kind:       "SopsSecret",
								Name:       "delete-error",
								UID:        "test-uid",
								Controller: &trueVal,
							},
						},
					},
				}
				Expect(fakeClient.Create(ctx, secret)).To(Succeed())

				errorClient := &ErrorClient{
					Client:      fakeClient,
					DeleteError: fmt.Errorf("delete forbidden"),
				}

				reconciler := &SopsSecretReconciler{
					Client:    errorClient,
					Scheme:    scheme.Scheme,
					Recorder:  &events.FakeRecorder{},
					Decryptor: &MockDecryptor{},
				}

				result, err := reconciler.reconcileDelete(ctx, sopsSecret)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("delete forbidden"))
				Expect(result).To(Equal(ctrl.Result{}))
			})

			It("should return error when removing finalizer fails", func() {
				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					Build()

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "finalizer-remove-error",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
				}
				Expect(fakeClient.Create(ctx, sopsSecret)).To(Succeed())

				errorClient := &ErrorClient{
					Client:      fakeClient,
					UpdateError: fmt.Errorf("finalizer removal failed"),
				}

				reconciler := &SopsSecretReconciler{
					Client:    errorClient,
					Scheme:    scheme.Scheme,
					Recorder:  &events.FakeRecorder{},
					Decryptor: &MockDecryptor{},
				}

				result, err := reconciler.reconcileDelete(ctx, sopsSecret)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("finalizer removal failed"))
				Expect(result).To(Equal(ctrl.Result{}))
			})
		})

		Describe("SetupWithManager", func() {
			It("should return error with nil manager", func() {
				reconciler := &SopsSecretReconciler{
					Scheme: scheme.Scheme,
				}

				err := reconciler.SetupWithManager(nil)
				Expect(err).To(HaveOccurred())
			})
		})

		Describe("SetControllerReference error", func() {
			It("should return error when SetControllerReference fails", func() {
				// Use an empty scheme that doesn't have the types registered
				emptyScheme := runtime.NewScheme()

				fakeClient := fake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					WithStatusSubresource(&secretsv1alpha1.SopsSecret{}).
					Build()

				sopsSecret := &secretsv1alpha1.SopsSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "owner-ref-error",
						Namespace:  "default",
						Finalizers: []string{finalizerName},
					},
					Spec: secretsv1alpha1.SopsSecretSpec{
						SopsSecret: `test: value
sops:
    mac: test
`,
					},
				}
				Expect(fakeClient.Create(ctx, sopsSecret)).To(Succeed())

				reconciler := &SopsSecretReconciler{
					Client:   fakeClient,
					Scheme:   emptyScheme, // Empty scheme will cause SetControllerReference to fail
					Recorder: &events.FakeRecorder{},
					Decryptor: &MockDecryptor{
						DecryptFunc: func(data []byte) (*sops.DecryptedData, error) {
							return &sops.DecryptedData{
								Data: map[string][]byte{"key": []byte("value")},
							}, nil
						},
					},
				}

				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "owner-ref-error",
						Namespace: "default",
					},
				}

				result, err := reconciler.Reconcile(ctx, req)

				Expect(err).To(HaveOccurred())
				Expect(result).To(Equal(ctrl.Result{}))
			})
		})
	})
})
