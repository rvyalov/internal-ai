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

package telemetry

import (
	"github.com/segmentio/analytics-go"

	"github.com/Mirantis/hmc/internal/build"
)

const (
	managedClusterCreateEvent    = "managed-cluster-create"
	managedClusterHeartbeatEvent = "managed-cluster-heartbeat"
)

func TrackManagedClusterCreate(id, managedClusterID, template string, dryRun bool) error {
	props := map[string]any{
		"hmcVersion":       build.Version,
		"managedClusterID": managedClusterID,
		"template":         template,
		"dryRun":           dryRun,
	}
	return TrackEvent(managedClusterCreateEvent, id, props)
}

func TrackManagedClusterHeartbeat(id, managedClusterID, clusterID, template, templateHelmChartVersion string, providers []string) error {
	props := map[string]any{
		"hmcVersion":               build.Version,
		"managedClusterID":         managedClusterID,
		"clusterID":                clusterID,
		"template":                 template,
		"templateHelmChartVersion": templateHelmChartVersion,
		"providers":                providers,
	}
	return TrackEvent(managedClusterHeartbeatEvent, id, props)
}

func TrackEvent(name, id string, properties map[string]any) error {
	if analyticsClient == nil {
		return nil
	}
	return analyticsClient.Enqueue(analytics.Track{
		AnonymousId: id,
		Event:       name,
		Properties:  properties,
	})
}
