package service

import (
	"fmt"
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/kube"
	"github.com/fairwindsops/polaris/pkg/validator"
	"strings"
)

func CreateKubeOverview(kubeResources *kube.ResourceProvider) KubeOverview {
	return KubeOverview{
		Cluster: ClusterSummary{
			Name:            kubeResources.SourceName,
			Version:         kubeResources.ServerVersion,
			NodesCount:      len(kubeResources.Nodes),
			NamespacesCount: len(kubeResources.Namespaces),
			PodsCount:       len(kubeResources.Pods),
		},
		Checks: make([]Check, 0),
	}
}

type KubeOverview struct {
	Cluster             ClusterSummary  `json:"cluster"`
	Checks              []Check         `json:"checks"`
	CheckGroupSummary   []ResultSummary `json:"checkGroupSummary"`
	NamespaceSummary    []ResultSummary `json:"namespaceSummary"`
	CheckResultsSummary ResultSummary   `json:"checkResultsSummary"`
}

type ClusterSummary struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	NodesCount      int    `json:"nodes"`
	NamespacesCount int    `json:"namespaces"`
	PodsCount       int    `json:"pods"`
	Score           uint   `json:"score"`
}

type Check struct {
	Id               string      `json:"id"`
	GroupName        string      `json:"group"`
	ResourceCategory string      `json:"category"`
	ResourceFullName string      `json:"resourceName"`
	Result           CheckResult `json:"result"`
}

type CheckResult string

const(
    Success CheckResult = "success"
    Error = "error"
    Warning = "warning"
    NoData = "nodata"
)

type ResultSummary struct {
	Name      string `json:"resultName"`
	Successes uint
	Warnings  uint
	Errors    uint
	NoDatas   uint
}

func (result *ResultSummary) Add(checkResult CheckResult){
	switch checkResult {
	case Success:
		result.Successes++
	case Error:
		result.Errors++
	case Warning:
		result.Warnings++
	case NoData:
		result.NoDatas++
	}
}

func (overview *KubeOverview) AddPolarisResults(auditData *validator.AuditData) {
	for ns := range auditData.NamespacedResults {
		for j := range auditData.NamespacedResults[ns].CronJobResults {
			checks := mapController(ns, auditData.NamespacedResults[ns].CronJobResults[j], "cron-jobs")
			overview.Checks = append(overview.Checks, checks...)
		}
		for j := range auditData.NamespacedResults[ns].JobResults {
			checks := mapController(ns, auditData.NamespacedResults[ns].JobResults[j], "jobs")
			overview.Checks = append(overview.Checks, checks...)
		}
		for j := range auditData.NamespacedResults[ns].DaemonSetResults {
			checks := mapController(ns, auditData.NamespacedResults[ns].DaemonSetResults[j], "daemon-sets")
			overview.Checks = append(overview.Checks, checks...)
		}
		for j := range auditData.NamespacedResults[ns].DeploymentResults {
			checks := mapController(ns, auditData.NamespacedResults[ns].DeploymentResults[j], "deployments")
			overview.Checks = append(overview.Checks, checks...)
		}
		for j := range auditData.NamespacedResults[ns].ReplicationControllerResults {
			checks := mapController(ns, auditData.NamespacedResults[ns].ReplicationControllerResults[j], "rc")
			overview.Checks = append(overview.Checks, checks...)
		}
		for j := range auditData.NamespacedResults[ns].StatefulSetResults {
			checks := mapController(ns, auditData.NamespacedResults[ns].StatefulSetResults[j], "stateful-sets")
			overview.Checks = append(overview.Checks, checks...)
		}
	}
}

func (overview *KubeOverview) CalculateSummaries() {
	nsDict := make(map[string]*ResultSummary, 0)
	groupDict := make(map[string]*ResultSummary, 0)
	checks := ResultSummary{
		Name:"Overall Checks Summary",
	}

	for _, check := range overview.Checks {
		// increment General counter
		checks.Add(check.Result)

		// increment Groups counter
		if _, ok := groupDict[check.GroupName]; !ok {
			groupDict[check.GroupName] = &ResultSummary{
				Name: check.GroupName,
			}
		}
		groupDict[check.GroupName].Add(check.Result)

		// increment Namespace counter only for polaris check
		if strings.HasPrefix(check.GroupName, "polaris.") {
			ns := strings.Split(check.ResourceFullName, "/")[2]
			if _, ok := nsDict[ns]; !ok {
				nsDict[ns] = &ResultSummary{
					Name:      ns,
				}
			}
			nsDict[ns].Add(check.Result)
		}
	}

	overview.CheckResultsSummary = checks

	i := 0
	overview.CheckGroupSummary = make([]ResultSummary, len(groupDict))
	for _, v := range groupDict {
		overview.CheckGroupSummary[i] = *v
		i++
	}

	i = 0
	overview.NamespaceSummary = make([]ResultSummary, len(nsDict))
	for _, v := range nsDict {
		overview.NamespaceSummary[i] = *v
		i++
	}
}

func mapController(ns string, result validator.ControllerResult, group string) []Check {
	prefix := fmt.Sprintf("/ns/%s/%s/%s", ns, group, result.Name)
	checks := convertToChecks(&result.PodResult, group, prefix)
	return checks
}

func convertToChecks(podResult *validator.PodResult, category string, prefix string) []Check {
	checks := make([]Check, 0)
	for i := range podResult.Messages {
		message := podResult.Messages[i]
		check := Check{
			GroupName:        fmt.Sprintf("polaris.%s", message.Category),
			Id:               fmt.Sprintf("polaris.%s", message.ID),
			ResourceCategory: category,
			ResourceFullName: fmt.Sprintf("%s/pods", prefix),
			Result:           toCheckResult(message.Type),
		}
		checks = append(checks, check)
	}

	for i := range podResult.ContainerResults {
		container := podResult.ContainerResults[i]
		for j := range podResult.ContainerResults[i].Messages {
			message := podResult.ContainerResults[i].Messages[j]
			check := Check{
				GroupName:        fmt.Sprintf("polaris.%s", message.Category),
				Id:               fmt.Sprintf("polaris.%s", message.ID),
				ResourceCategory: category,
				ResourceFullName: fmt.Sprintf("%s/container/%s", prefix, container.Name),
				Result:           toCheckResult(message.Type),
			}
			checks = append(checks, check)
		}
	}

	return checks
}

func toCheckResult(polarisResult validator.MessageType) CheckResult {
	switch polarisResult {
	case validator.MessageTypeSuccess:
		return Success
	case validator.MessageTypeError:
		return Error
	case validator.MessageTypeWarning:
		return Warning
	default:
		return NoData
	}
}
