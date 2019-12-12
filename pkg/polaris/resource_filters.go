package polaris

import (
	polaris "github.com/fairwindsops/polaris/pkg/kube"
)

func filterByNamespace(rp *polaris.ResourceProvider, namespaces ...string) {
	if len(namespaces) == 0 {
		return
	}

	filterNamespaces(rp, namespaces)
	filterDeployments(rp, namespaces)
	filterStatefulSets(rp, namespaces)
	filterDaemonSets(rp, namespaces)
	filterJobs(rp, namespaces)
	filterCronJobs(rp, namespaces)
	filterReplicationControllers(rp, namespaces)
	filterPods(rp, namespaces)
}

func filterNamespaces(rp *polaris.ResourceProvider, namespaces []string) {
	filtered := rp.Namespaces[:0]
	for _, x := range rp.Namespaces {
		for _, ns := range namespaces {
			if x.Name == ns {
				filtered = append(filtered, x)
			}
		}
	}

	rp.Namespaces = filtered
}

func filterDeployments(rp *polaris.ResourceProvider, namespaces []string) {
	filtered := rp.Deployments[:0]
	for _, x := range rp.Deployments {
		for _, ns := range namespaces {
			if x.Namespace == ns {
				filtered = append(filtered, x)
			}
		}
	}

	rp.Deployments = filtered
}

func filterStatefulSets(rp *polaris.ResourceProvider, namespaces []string) {
	filtered := rp.StatefulSets[:0]
	for _, x := range rp.StatefulSets {
		for _, ns := range namespaces {
			if x.Namespace == ns {
				filtered = append(filtered, x)
			}
		}
	}

	rp.StatefulSets = filtered
}

func filterDaemonSets(rp *polaris.ResourceProvider, namespaces []string) {
	filtered := rp.DaemonSets[:0]
	for _, x := range rp.DaemonSets {
		for _, ns := range namespaces {
			if x.Namespace == ns {
				filtered = append(filtered, x)
			}
		}
	}

	rp.DaemonSets = filtered
}

func filterJobs(rp *polaris.ResourceProvider, namespaces []string) {
	filtered := rp.Jobs[:0]
	for _, x := range rp.Jobs {
		for _, ns := range namespaces {
			if x.Namespace == ns {
				filtered = append(filtered, x)
			}
		}
	}

	rp.Jobs = filtered
}

func filterCronJobs(rp *polaris.ResourceProvider, namespaces []string) {
	filtered := rp.CronJobs[:0]
	for _, x := range rp.CronJobs {
		for _, ns := range namespaces {
			if x.Namespace == ns {
				filtered = append(filtered, x)
			}
		}
	}

	rp.CronJobs = filtered
}

func filterReplicationControllers(rp *polaris.ResourceProvider, namespaces []string) {
	filtered := rp.ReplicationControllers[:0]
	for _, x := range rp.ReplicationControllers {
		for _, ns := range namespaces {
			if x.Namespace == ns {
				filtered = append(filtered, x)
			}
		}
	}

	rp.ReplicationControllers = filtered
}

func filterPods(rp *polaris.ResourceProvider, namespaces []string) {
	filtered := rp.Pods[:0]
	for _, x := range rp.Pods {
		for _, ns := range namespaces {
			if x.Namespace == ns {
				filtered = append(filtered, x)
			}
		}
	}

	rp.Pods = filtered
}
