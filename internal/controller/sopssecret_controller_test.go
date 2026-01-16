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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secretsv1alpha1 "github.com/scalaric/sops-operator/api/v1alpha1"
)

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
})
