// Copyright 2019 FairwindsOps Inc
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

package validator

import (
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/config"
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/validator/messages"
	corev1 "k8s.io/api/core/v1"
)

// PodValidation tracks validation failures associated with a Pod.
type PodValidation struct {
	*ResourceValidation
	Pod *corev1.PodSpec
}

// ValidatePod validates that each pod conforms to the Polaris config, returns a ResourceResult.
func ValidatePod(conf *config.PolarisConfiguration, pod *corev1.PodSpec, controllerName string, controllerType config.SupportedController, scans *ScansSummary) PodResult {
	pv := PodValidation{
		Pod:                pod,
		ResourceValidation: &ResourceValidation{},
	}

	pv.validateSecurity(conf, controllerName)
	pv.validateNetworking(conf, controllerName)

	pRes := PodResult{
		Messages:         pv.messages(),
		ContainerResults: []ContainerResult{},
		Summary:          pv.summary(),
		podSpec:          *pod,
	}

	pv.validateContainers(pod.InitContainers, &pRes, conf, controllerName, controllerType, true, scans)
	pv.validateContainers(pod.Containers, &pRes, conf, controllerName, controllerType, false, scans)

	for _, cRes := range pRes.ContainerResults {
		pRes.Summary.appendResults(*cRes.Summary)
	}

	return pRes
}

func (pv *PodValidation) validateContainers(containers []corev1.Container, pRes *PodResult, conf *config.PolarisConfiguration, controllerName string, controllerType config.SupportedController, isInit bool, scans *ScansSummary) {
	for _, container := range containers {
		cRes := ValidateContainer(&container, pRes, conf, controllerName, controllerType, isInit, scans)
		pRes.ContainerResults = append(pRes.ContainerResults, cRes)
	}
}

func (pv *PodValidation) validateSecurity(conf *config.PolarisConfiguration, controllerName string) {
	category := messages.CategorySecurity

	name := "HostIPCSet"
	if conf.IsActionable(conf.Security, name, controllerName) {
		id := config.GetIDFromField(conf.Security, name)
		if pv.Pod.HostIPC {
			pv.addFailure(messages.HostIPCFailure, conf.Security.HostIPCSet, category, id)
		} else {
			pv.addSuccess(messages.HostIPCSuccess, category, id)
		}
	}

	name = "HostPIDSet"
	if conf.IsActionable(conf.Security, name, controllerName) {
		id := config.GetIDFromField(conf.Security, name)
		if pv.Pod.HostPID {
			pv.addFailure(messages.HostPIDFailure, conf.Security.HostPIDSet, category, id)
		} else {
			pv.addSuccess(messages.HostPIDSuccess, category, id)
		}
	}
}

func (pv *PodValidation) validateNetworking(conf *config.PolarisConfiguration, controllerName string) {
	category := messages.CategoryNetworking

	name := "HostNetworkSet"
	if conf.IsActionable(conf.Networking, name, controllerName) {
		id := config.GetIDFromField(conf.Networking, name)
		if pv.Pod.HostNetwork {
			pv.addFailure(messages.HostNetworkFailure, conf.Networking.HostNetworkSet, category, id)
		} else {
			pv.addSuccess(messages.HostNetworkSuccess, category, id)
		}
	}
}
