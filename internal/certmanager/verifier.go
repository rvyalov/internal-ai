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

package certmanager

import (
	"context"

	"github.com/cert-manager/cert-manager/pkg/util/cmapichecker"
	"k8s.io/client-go/rest"
)

func VerifyAPI(ctx context.Context, restcfg *rest.Config, namespace string) error {
	checker, err := cmapichecker.New(restcfg, namespace)
	if err != nil {
		return err
	}
	err = checker.Check(ctx)
	if err != nil {
		return err
	}
	return nil
}
