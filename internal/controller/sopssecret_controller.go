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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"

	secretsv1alpha1 "github.com/gg/sops-operator/api/v1alpha1"
	"github.com/gg/sops-operator/pkg/sops"
)

const (
	finalizerName = "secrets.gg.io/finalizer"

	// Event reasons
	ReasonDecrypted      = "Decrypted"
	ReasonDecryptFailed  = "DecryptFailed"
	ReasonSecretCreated  = "SecretCreated"
	ReasonSecretUpdated  = "SecretUpdated"
	ReasonSecretDeleted  = "SecretDeleted"
	ReasonValidationFail = "ValidationFailed"
)

// SopsSecretReconciler reconciles a SopsSecret object
type SopsSecretReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder
	Decryptor *sops.Decryptor
}

// decryptPayload is the structure we serialize for SOPS decryption.
// It only contains the fields that SOPS encrypted.
type decryptPayload struct {
	Spec struct {
		Data map[string]interface{} `json:"data"`
	} `json:"spec"`
	Sops *secretsv1alpha1.SopsMetadata `json:"sops"`
}

// convertDataToInterface converts apiextensionsv1.JSON map to interface{} map for serialization.
func convertDataToInterface(data map[string]apiextensionsv1.JSON) map[string]interface{} {
	result := make(map[string]interface{}, len(data))
	for k, v := range data {
		var val interface{}
		if err := json.Unmarshal(v.Raw, &val); err != nil {
			// If unmarshal fails, use raw bytes as string
			result[k] = string(v.Raw)
		} else {
			result[k] = val
		}
	}
	return result
}

// +kubebuilder:rbac:groups=secrets.gg.io,resources=sopssecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.gg.io,resources=sopssecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.gg.io,resources=sopssecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *SopsSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the SopsSecret
	sopsSecret := &secretsv1alpha1.SopsSecret{}
	if err := r.Get(ctx, req.NamespacedName, sopsSecret); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get SopsSecret")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !sopsSecret.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, sopsSecret)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(sopsSecret, finalizerName) {
		controllerutil.AddFinalizer(sopsSecret, finalizerName)
		if err := r.Update(ctx, sopsSecret); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Check if suspended
	if sopsSecret.Spec.Suspend {
		log.Info("SopsSecret is suspended, skipping reconciliation")
		return ctrl.Result{}, nil
	}

	// Build the payload for SOPS decryption
	payload := decryptPayload{
		Sops: sopsSecret.Sops,
	}
	payload.Spec.Data = convertDataToInterface(sopsSecret.Spec.Data)

	// Serialize to YAML for hashing and decryption
	payloadYAML, err := yaml.Marshal(payload)
	if err != nil {
		log.Error(err, "Failed to serialize SopsSecret for decryption")
		return ctrl.Result{}, err
	}

	// Calculate hash of encrypted data
	hash := calculateHash(string(payloadYAML))

	// Check if we need to re-decrypt
	if sopsSecret.Status.LastDecryptedHash == hash &&
		sopsSecret.Status.ObservedGeneration == sopsSecret.Generation {
		// No changes, verify secret still exists
		secretName := r.getSecretName(sopsSecret)
		existingSecret := &corev1.Secret{}
		err := r.Get(ctx, types.NamespacedName{
			Name:      secretName,
			Namespace: sopsSecret.Namespace,
		}, existingSecret)

		if err == nil {
			// Secret exists and no changes, nothing to do
			return ctrl.Result{}, nil
		}
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		// Secret was deleted, need to recreate
	}

	// Validate that sops metadata exists
	if sopsSecret.Sops == nil {
		r.setCondition(sopsSecret, secretsv1alpha1.ConditionTypeDecrypted, metav1.ConditionFalse,
			"ValidationFailed", "Missing sops metadata block - run 'sops -e -i' on the CRD file")
		r.setCondition(sopsSecret, secretsv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			"ValidationFailed", "SOPS metadata not found")
		r.Recorder.Event(sopsSecret, corev1.EventTypeWarning, ReasonValidationFail, "Missing sops metadata block")
		return r.updateStatus(ctx, sopsSecret)
	}

	// Validate MAC exists
	if sopsSecret.Sops.Mac == "" {
		r.setCondition(sopsSecret, secretsv1alpha1.ConditionTypeDecrypted, metav1.ConditionFalse,
			"ValidationFailed", "Missing MAC in sops metadata")
		r.setCondition(sopsSecret, secretsv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			"ValidationFailed", "SOPS MAC not found")
		r.Recorder.Event(sopsSecret, corev1.EventTypeWarning, ReasonValidationFail, "Missing MAC in sops metadata")
		return r.updateStatus(ctx, sopsSecret)
	}

	// Decrypt the data
	decrypted, err := r.Decryptor.DecryptCRD(payloadYAML)
	if err != nil {
		log.Error(err, "Failed to decrypt SopsSecret")
		r.setCondition(sopsSecret, secretsv1alpha1.ConditionTypeDecrypted, metav1.ConditionFalse,
			"DecryptFailed", err.Error())
		r.setCondition(sopsSecret, secretsv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			"DecryptFailed", "Failed to decrypt SOPS data")
		r.Recorder.Event(sopsSecret, corev1.EventTypeWarning, ReasonDecryptFailed, err.Error())
		return r.updateStatus(ctx, sopsSecret)
	}

	r.setCondition(sopsSecret, secretsv1alpha1.ConditionTypeDecrypted, metav1.ConditionTrue,
		"Success", "Successfully decrypted SOPS data")
	r.Recorder.Event(sopsSecret, corev1.EventTypeNormal, ReasonDecrypted, "Successfully decrypted SOPS data")

	// Create or update the Kubernetes Secret
	secret := r.buildSecret(sopsSecret, decrypted)

	// Set owner reference
	if err := controllerutil.SetControllerReference(sopsSecret, secret, r.Scheme); err != nil {
		log.Error(err, "Failed to set owner reference")
		return ctrl.Result{}, err
	}

	// Create or update the secret
	existingSecret := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      secret.Name,
		Namespace: secret.Namespace,
	}, existingSecret)

	if apierrors.IsNotFound(err) {
		// Create new secret
		if err := r.Create(ctx, secret); err != nil {
			log.Error(err, "Failed to create Secret")
			return ctrl.Result{}, err
		}
		log.Info("Created Secret", "name", secret.Name)
		r.Recorder.Eventf(sopsSecret, corev1.EventTypeNormal, ReasonSecretCreated,
			"Created Secret %s", secret.Name)
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		// Update existing secret
		existingSecret.Data = secret.Data
		existingSecret.Labels = secret.Labels
		existingSecret.Annotations = secret.Annotations
		existingSecret.Type = secret.Type

		if err := r.Update(ctx, existingSecret); err != nil {
			log.Error(err, "Failed to update Secret")
			return ctrl.Result{}, err
		}
		log.Info("Updated Secret", "name", secret.Name)
		r.Recorder.Eventf(sopsSecret, corev1.EventTypeNormal, ReasonSecretUpdated,
			"Updated Secret %s", secret.Name)
	}

	// Update status
	now := metav1.Now()
	sopsSecret.Status.SecretName = secret.Name
	sopsSecret.Status.LastDecryptedHash = hash
	sopsSecret.Status.LastDecryptedTime = &now
	sopsSecret.Status.ObservedGeneration = sopsSecret.Generation
	r.setCondition(sopsSecret, secretsv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		"Success", fmt.Sprintf("Secret %s is up to date", secret.Name))

	return r.updateStatus(ctx, sopsSecret)
}

func (r *SopsSecretReconciler) reconcileDelete(ctx context.Context, sopsSecret *secretsv1alpha1.SopsSecret) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if controllerutil.ContainsFinalizer(sopsSecret, finalizerName) {
		// Delete the managed secret if it exists
		secretName := r.getSecretName(sopsSecret)
		secret := &corev1.Secret{}
		err := r.Get(ctx, types.NamespacedName{
			Name:      secretName,
			Namespace: sopsSecret.Namespace,
		}, secret)

		if err == nil {
			// Check if we own this secret
			if metav1.IsControlledBy(secret, sopsSecret) {
				if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
					return ctrl.Result{}, err
				}
				log.Info("Deleted managed Secret", "name", secretName)
				r.Recorder.Eventf(sopsSecret, corev1.EventTypeNormal, ReasonSecretDeleted,
					"Deleted Secret %s", secretName)
			}
		} else if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}

		// Remove finalizer
		controllerutil.RemoveFinalizer(sopsSecret, finalizerName)
		if err := r.Update(ctx, sopsSecret); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *SopsSecretReconciler) buildSecret(sopsSecret *secretsv1alpha1.SopsSecret, decrypted *sops.DecryptedData) *corev1.Secret {
	secretName := r.getSecretName(sopsSecret)
	secretType := sopsSecret.Spec.SecretType
	if secretType == "" {
		secretType = corev1.SecretTypeOpaque
	}

	labels := make(map[string]string)
	labels["app.kubernetes.io/managed-by"] = "sops-operator"
	labels["secrets.gg.io/sopssecret"] = sopsSecret.Name
	for k, v := range sopsSecret.Spec.SecretLabels {
		labels[k] = v
	}

	annotations := make(map[string]string)
	annotations["secrets.gg.io/source"] = fmt.Sprintf("%s/%s", sopsSecret.Namespace, sopsSecret.Name)
	for k, v := range sopsSecret.Spec.SecretAnnotations {
		annotations[k] = v
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
			Namespace:   sopsSecret.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Type: secretType,
		Data: decrypted.Data,
	}
}

func (r *SopsSecretReconciler) getSecretName(sopsSecret *secretsv1alpha1.SopsSecret) string {
	if sopsSecret.Spec.SecretName != "" {
		return sopsSecret.Spec.SecretName
	}
	return sopsSecret.Name
}

func (r *SopsSecretReconciler) setCondition(sopsSecret *secretsv1alpha1.SopsSecret, condType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&sopsSecret.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: sopsSecret.Generation,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

func (r *SopsSecretReconciler) updateStatus(ctx context.Context, sopsSecret *secretsv1alpha1.SopsSecret) (ctrl.Result, error) {
	if err := r.Status().Update(ctx, sopsSecret); err != nil {
		return ctrl.Result{}, err
	}

	// Requeue after 5 minutes to periodically verify secret
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func calculateHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// SetupWithManager sets up the controller with the Manager.
func (r *SopsSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.SopsSecret{}).
		Owns(&corev1.Secret{}).
		Named("sopssecret").
		Complete(r)
}
