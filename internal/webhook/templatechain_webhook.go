// Copyright 2024
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package webhook

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/Mirantis/hmc/api/v1alpha1"
)

var errInvalidTemplateChainSpec = errors.New("the template chain spec is invalid")

type ClusterTemplateChainValidator struct {
	client.Client
}

func (in *ClusterTemplateChainValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	in.Client = mgr.GetClient()
	return ctrl.NewWebhookManagedBy(mgr).
		For(&v1alpha1.ClusterTemplateChain{}).
		WithValidator(in).
		WithDefaulter(in).
		Complete()
}

var (
	_ webhook.CustomValidator = &ClusterTemplateChainValidator{}
	_ webhook.CustomDefaulter = &ClusterTemplateChainValidator{}
)

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type.
func (*ClusterTemplateChainValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	chain, ok := obj.(*v1alpha1.ClusterTemplateChain)
	if !ok {
		return admission.Warnings{"Wrong object"}, apierrors.NewBadRequest(fmt.Sprintf("expected ClusterTemplateChain but got a %T", obj))
	}

	warnings := isTemplateChainValid(chain.Spec)
	if len(warnings) > 0 {
		return warnings, errInvalidTemplateChainSpec
	}
	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type.
func (*ClusterTemplateChainValidator) ValidateUpdate(_ context.Context, _, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type.
func (*ClusterTemplateChainValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// Default implements webhook.Defaulter so a webhook will be registered for the type.
func (*ClusterTemplateChainValidator) Default(_ context.Context, _ runtime.Object) error {
	return nil
}

type ServiceTemplateChainValidator struct {
	client.Client
}

func (in *ServiceTemplateChainValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	in.Client = mgr.GetClient()
	return ctrl.NewWebhookManagedBy(mgr).
		For(&v1alpha1.ServiceTemplateChain{}).
		WithValidator(in).
		WithDefaulter(in).
		Complete()
}

var (
	_ webhook.CustomValidator = &ServiceTemplateChainValidator{}
	_ webhook.CustomDefaulter = &ServiceTemplateChainValidator{}
)

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type.
func (*ServiceTemplateChainValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	chain, ok := obj.(*v1alpha1.ServiceTemplateChain)
	if !ok {
		return admission.Warnings{"Wrong object"}, apierrors.NewBadRequest(fmt.Sprintf("expected ServiceTemplateChain but got a %T", obj))
	}
	warnings := isTemplateChainValid(chain.Spec)
	if len(warnings) > 0 {
		return warnings, errInvalidTemplateChainSpec
	}
	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type.
func (*ServiceTemplateChainValidator) ValidateUpdate(_ context.Context, _, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type.
func (*ServiceTemplateChainValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// Default implements webhook.Defaulter so a webhook will be registered for the type.
func (*ServiceTemplateChainValidator) Default(_ context.Context, _ runtime.Object) error {
	return nil
}

func isTemplateChainValid(spec v1alpha1.TemplateChainSpec) admission.Warnings {
	supportedTemplates := make(map[string]bool)
	availableForUpgrade := make(map[string]bool)
	for _, supportedTemplate := range spec.SupportedTemplates {
		supportedTemplates[supportedTemplate.Name] = true
		for _, template := range supportedTemplate.AvailableUpgrades {
			availableForUpgrade[template.Name] = true
		}
	}
	warnings := admission.Warnings{}
	for template := range availableForUpgrade {
		if !supportedTemplates[template] {
			warnings = append(warnings, fmt.Sprintf("template %s is allowed for upgrade but is not present in the list of spec.SupportedTemplates", template))
		}
	}
	return warnings
}
