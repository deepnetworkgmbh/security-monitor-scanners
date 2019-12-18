package service

import (
	"fmt"
	scanner "github.com/deepnetworkgmbh/security-monitor-scanners/pkg/imagescanner"
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/kube"
	"github.com/fairwindsops/polaris/pkg/validator"
	"k8s.io/api/core/v1"
	"strings"
)

func CreateKubeOverview(kube *kube.ResourceProvider, auditData *validator.AuditData, imageScanner *scanner.ImageScanner) *KubeOverview {
	overview := KubeOverview{
		Cluster: ClusterSummary{
			Name:            kube.SourceName,
			Version:         kube.ServerVersion,
			NodesCount:      len(kube.Nodes),
			NamespacesCount: len(kube.Namespaces),
			PodsCount:       len(kube.Pods),
		},
		Checks: make([]Check, 0),
	}
	overview.addPolarisResults(auditData)
	overview.addImageScanResults(kube, imageScanner)
	overview.calculateSummaries()

	return &overview;
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

func (overview *KubeOverview) addPolarisResults(auditData *validator.AuditData) {
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

func (overview *KubeOverview) addImageScanResults(kube *kube.ResourceProvider, imageScanner *scanner.ImageScanner){
	temp := imageScansHelper{
		images:    make(map[string]bool, 0),
		resources: make(map[string]string, 0),
		scans:     make(map[string]scanner.ImageScanResultSummary, 0),
	}

	for i := range kube.Deployments {
		prefix := fmt.Sprintf("/ns/%s/deployments/%s", kube.Deployments[i].Namespace, kube.Deployments[i].Name)
		parsePodTemplate(&kube.Deployments[i].Spec.Template.Spec, prefix, &temp)
	}
	for i := range kube.DaemonSets {
		prefix := fmt.Sprintf("/ns/%s/daemon-sets/%s", kube.DaemonSets[i].Namespace, kube.DaemonSets[i].Name)
		parsePodTemplate(&kube.DaemonSets[i].Spec.Template.Spec, prefix, &temp)
	}
	for i := range kube.StatefulSets {
		prefix := fmt.Sprintf("/ns/%s/stateful-sets/%s", kube.StatefulSets[i].Namespace, kube.StatefulSets[i].Name)
		parsePodTemplate(&kube.StatefulSets[i].Spec.Template.Spec, prefix, &temp)
	}
	for i := range kube.ReplicationControllers {
		prefix := fmt.Sprintf("/ns/%s/rc/%s", kube.ReplicationControllers[i].Namespace, kube.ReplicationControllers[i].Name)
		parsePodTemplate(&kube.ReplicationControllers[i].Spec.Template.Spec, prefix, &temp)
	}
	for i := range kube.CronJobs {
		prefix := fmt.Sprintf("/ns/%s/cron-jobs/%s", kube.CronJobs[i].Namespace, kube.CronJobs[i].Name)
		parsePodTemplate(&kube.CronJobs[i].Spec.JobTemplate.Spec.Template.Spec, prefix, &temp)
	}
	for i := range kube.Jobs {
		prefix := fmt.Sprintf("/ns/%s/jobs/%s", kube.Jobs[i].Namespace, kube.Jobs[i].Name)
		parsePodTemplate(&kube.Jobs[i].Spec.Template.Spec, prefix, &temp)
	}

	i := 0
	images := make([]string, len(temp.images))
	for k := range temp.images {
		images[i] = k
		i++
	}

	scanResults, _ := imageScanner.GetScanResults(images)
	for _, scan := range scanResults {
		temp.scans[scan.Image] = scan
	}

	checks := make([]Check, 0)
	for id, tag := range temp.resources {
		if val, ok := temp.scans[tag]; ok {
			check := Check{
				GroupName:        "trivy.cve-scan",
				Id:               "trivy.cveScan",
				ResourceCategory: "containers",
				ResourceFullName: id,
				Result:           fromTrivyToCheckResult(val.GetSeverity()),
			}
			checks = append(checks, check)
		}
	}

	overview.Checks = append(overview.Checks, checks...)
}

type imageScansHelper struct {
	images    map[string]bool
	resources map[string]string
	scans     map[string]scanner.ImageScanResultSummary
}

func parsePodTemplate(spec *v1.PodSpec, prefix string, temp *imageScansHelper) {
	for i := range spec.Containers {
		id := fmt.Sprintf("%s/containers/%s", prefix, spec.Containers[i].Name)
		temp.images[spec.Containers[i].Image] = true
		temp.resources[id] = spec.Containers[i].Image
	}

	for i := range spec.InitContainers {
		id := fmt.Sprintf("%s/init-containers/%s", prefix, spec.Containers[i].Name)
		temp.images[spec.Containers[i].Image] = true
		temp.resources[id] = spec.Containers[i].Image
	}
}

func (overview *KubeOverview) calculateSummaries() {
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
			Result:           fromPolarisToCheckResult(message.Type),
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
				ResourceFullName: fmt.Sprintf("%s/containers/%s", prefix, container.Name),
				Result:           fromPolarisToCheckResult(message.Type),
			}
			checks = append(checks, check)
		}
	}

	return checks
}

func fromPolarisToCheckResult(result validator.MessageType) CheckResult {
	switch result {
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

func fromTrivyToCheckResult(result scanner.TrivyResult) CheckResult {
	switch result {
	case scanner.Success:
		return Success
	case scanner.Error:
		return Error
	case scanner.Warning:
		return Warning
	case scanner.NoData:
		return NoData
	default:
		return NoData
	}
}
