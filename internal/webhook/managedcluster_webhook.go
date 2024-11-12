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
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	hmcv1alpha1 "github.com/Mirantis/hmc/api/v1alpha1"
)

type ManagedClusterValidator struct {
	client.Client
}

const invalidManagedClusterMsg = "the ManagedCluster is invalid"

var errClusterUpgradeForbidden = errors.New("cluster upgrade is forbidden")

func (v *ManagedClusterValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	v.Client = mgr.GetClient()
	return ctrl.NewWebhookManagedBy(mgr).
		For(&hmcv1alpha1.ManagedCluster{}).
		WithValidator(v).
		WithDefaulter(v).
		Complete()
}

var (
	_ webhook.CustomValidator = &ManagedClusterValidator{}
	_ webhook.CustomDefaulter = &ManagedClusterValidator{}
)

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type.
func (v *ManagedClusterValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	managedCluster, ok := obj.(*hmcv1alpha1.ManagedCluster)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("expected ManagedCluster but got a %T", obj))
	}

	template, err := v.getManagedClusterTemplate(ctx, managedCluster.Namespace, managedCluster.Spec.Template)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", invalidManagedClusterMsg, err)
	}

	if err := isTemplateValid(template.GetCommonStatus()); err != nil {
		return nil, fmt.Errorf("%s: %w", invalidManagedClusterMsg, err)
	}

	if err := validateK8sCompatibility(ctx, v.Client, template, managedCluster); err != nil {
		return admission.Warnings{"Failed to validate k8s version compatibility with ServiceTemplates"}, fmt.Errorf("failed to validate k8s compatibility: %w", err)
	}

	if err := v.validateCredential(ctx, managedCluster, template); err != nil {
		return nil, fmt.Errorf("%s: %w", invalidManagedClusterMsg, err)
	}

	if err := validateServices(ctx, v.Client, managedCluster.Namespace, managedCluster.Spec.Services); err != nil {
		return nil, fmt.Errorf("%s: %w", invalidManagedClusterMsg, err)
	}

	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type.
func (v *ManagedClusterValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldManagedCluster, ok := oldObj.(*hmcv1alpha1.ManagedCluster)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("expected ManagedCluster but got a %T", oldObj))
	}
	newManagedCluster, ok := newObj.(*hmcv1alpha1.ManagedCluster)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("expected ManagedCluster but got a %T", newObj))
	}
	oldTemplate := oldManagedCluster.Spec.Template
	newTemplate := newManagedCluster.Spec.Template

	template, err := v.getManagedClusterTemplate(ctx, newManagedCluster.Namespace, newTemplate)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", invalidManagedClusterMsg, err)
	}

	if oldTemplate != newTemplate {
		if !slices.Contains(oldManagedCluster.Status.AvailableUpgrades, newTemplate) {
			msg := fmt.Sprintf("Cluster can't be upgraded from %s to %s. This upgrade sequence is not allowed", oldTemplate, newTemplate)
			return admission.Warnings{msg}, errClusterUpgradeForbidden
		}

		if err := isTemplateValid(template.GetCommonStatus()); err != nil {
			return nil, fmt.Errorf("%s: %w", invalidManagedClusterMsg, err)
		}

		if err := validateK8sCompatibility(ctx, v.Client, template, newManagedCluster); err != nil {
			return admission.Warnings{"Failed to validate k8s version compatibility with ServiceTemplates"}, fmt.Errorf("failed to validate k8s compatibility: %w", err)
		}
	}

	if err := v.validateCredential(ctx, newManagedCluster, template); err != nil {
		return nil, fmt.Errorf("%s: %w", invalidManagedClusterMsg, err)
	}

	if err := validateServices(ctx, v.Client, newManagedCluster.Namespace, newManagedCluster.Spec.Services); err != nil {
		return nil, fmt.Errorf("%s: %w", invalidManagedClusterMsg, err)
	}

	return nil, nil
}

func validateK8sCompatibility(ctx context.Context, cl client.Client, template *hmcv1alpha1.ClusterTemplate, mc *hmcv1alpha1.ManagedCluster) error {
	if len(mc.Spec.Services) == 0 || template.Status.KubernetesVersion == "" {
		return nil // nothing to do
	}

	mcVersion, err := semver.NewVersion(template.Status.KubernetesVersion)
	if err != nil { // should never happen
		return fmt.Errorf("failed to parse k8s version %s of the ManagedCluster %s/%s: %w", template.Status.KubernetesVersion, mc.Namespace, mc.Name, err)
	}

	for _, v := range mc.Spec.Services {
		if v.Disable {
			continue
		}

		svcTpl := new(hmcv1alpha1.ServiceTemplate)
		if err := cl.Get(ctx, client.ObjectKey{Namespace: mc.Namespace, Name: v.Template}, svcTpl); err != nil {
			return fmt.Errorf("failed to get ServiceTemplate %s/%s: %w", mc.Namespace, v.Template, err)
		}

		constraint := svcTpl.Status.KubernetesConstraint
		if constraint == "" {
			continue
		}

		tplConstraint, err := semver.NewConstraint(constraint)
		if err != nil { // should never happen
			return fmt.Errorf("failed to parse k8s constrained version %s of the ServiceTemplate %s/%s: %w", constraint, mc.Namespace, v.Template, err)
		}

		if !tplConstraint.Check(mcVersion) {
			return fmt.Errorf("k8s version %s of the ManagedCluster %s/%s does not satisfy constrained version %s from the ServiceTemplate %s/%s",
				template.Status.KubernetesVersion, mc.Namespace, mc.Name,
				constraint, mc.Namespace, v.Template)
		}
	}

	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type.
func (*ManagedClusterValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// Default implements webhook.Defaulter so a webhook will be registered for the type.
func (v *ManagedClusterValidator) Default(ctx context.Context, obj runtime.Object) error {
	managedCluster, ok := obj.(*hmcv1alpha1.ManagedCluster)
	if !ok {
		return apierrors.NewBadRequest(fmt.Sprintf("expected ManagedCluster but got a %T", obj))
	}

	// Only apply defaults when there's no configuration provided;
	// if template ref is empty, then nothing to default
	if managedCluster.Spec.Config != nil || managedCluster.Spec.Template == "" {
		return nil
	}

	template, err := v.getManagedClusterTemplate(ctx, managedCluster.Namespace, managedCluster.Spec.Template)
	if err != nil {
		return fmt.Errorf("could not get template for the managedcluster: %w", err)
	}

	if err := isTemplateValid(template.GetCommonStatus()); err != nil {
		return fmt.Errorf("template is invalid: %w", err)
	}

	if template.Status.Config == nil {
		return nil
	}

	managedCluster.Spec.DryRun = true
	managedCluster.Spec.Config = &apiextensionsv1.JSON{Raw: template.Status.Config.Raw}

	return nil
}

func (v *ManagedClusterValidator) getManagedClusterTemplate(ctx context.Context, templateNamespace, templateName string) (tpl *hmcv1alpha1.ClusterTemplate, err error) {
	tpl = new(hmcv1alpha1.ClusterTemplate)
	return tpl, v.Get(ctx, client.ObjectKey{Namespace: templateNamespace, Name: templateName}, tpl)
}

func (v *ManagedClusterValidator) getManagedClusterCredential(ctx context.Context, credNamespace, credName string) (*hmcv1alpha1.Credential, error) {
	cred := &hmcv1alpha1.Credential{}
	credRef := client.ObjectKey{
		Name:      credName,
		Namespace: credNamespace,
	}
	if err := v.Get(ctx, credRef, cred); err != nil {
		return nil, err
	}
	return cred, nil
}

func isTemplateValid(status *hmcv1alpha1.TemplateStatusCommon) error {
	if !status.Valid {
		return fmt.Errorf("the template is not valid: %s", status.ValidationError)
	}

	return nil
}

func (v *ManagedClusterValidator) validateCredential(ctx context.Context, managedCluster *hmcv1alpha1.ManagedCluster, template *hmcv1alpha1.ClusterTemplate) error {
	if len(template.Status.Providers) == 0 {
		return fmt.Errorf("template %q has no providers defined", template.Name)
	}

	hasInfra := false
	for _, v := range template.Status.Providers {
		if strings.HasPrefix(v, "infrastructure-") {
			hasInfra = true
			break
		}
	}

	if !hasInfra {
		return fmt.Errorf("template %q has no infrastructure providers defined", template.Name)
	}

	cred, err := v.getManagedClusterCredential(ctx, managedCluster.Namespace, managedCluster.Spec.Credential)
	if err != nil {
		return err
	}

	if cred.Status.State != hmcv1alpha1.CredentialReady {
		return errors.New("credential is not Ready")
	}

	return isCredMatchTemplate(cred, template)
}

func isCredMatchTemplate(cred *hmcv1alpha1.Credential, template *hmcv1alpha1.ClusterTemplate) error {
	idtyKind := cred.Spec.IdentityRef.Kind

	errMsg := func(provider string) error {
		return fmt.Errorf("wrong kind of the ClusterIdentity %q for provider %q", idtyKind, provider)
	}

	for _, provider := range template.Status.Providers {
		switch provider {
		case "infrastructure-aws":
			if idtyKind != "AWSClusterStaticIdentity" &&
				idtyKind != "AWSClusterRoleIdentity" &&
				idtyKind != "AWSClusterControllerIdentity" {
				return errMsg(provider)
			}
		case "infrastructure-azure":
			if idtyKind != "AzureClusterIdentity" {
				return errMsg(provider)
			}
		case "infrastructure-vsphere":
			if idtyKind != "VSphereClusterIdentity" {
				return errMsg(provider)
			}
		default:
			if strings.HasPrefix(provider, "infrastructure-") {
				return fmt.Errorf("unsupported infrastructure provider %s", provider)
			}
		}
	}

	return nil
}
