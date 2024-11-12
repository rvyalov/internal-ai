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

package vsphere

import (
	"github.com/Mirantis/hmc/test/e2e/managedcluster"
)

func CheckEnv() {
	managedcluster.ValidateDeploymentVars([]string{
		"VSPHERE_USER",
		"VSPHERE_PASSWORD",
		"VSPHERE_SERVER",
		"VSPHERE_THUMBPRINT",
		"VSPHERE_DATACENTER",
		"VSPHERE_DATASTORE",
		"VSPHERE_RESOURCEPOOL",
		"VSPHERE_FOLDER",
		"VSPHERE_CONTROL_PLANE_ENDPOINT",
		"VSPHERE_VM_TEMPLATE",
		"VSPHERE_NETWORK",
		"VSPHERE_SSH_KEY",
	})
}
