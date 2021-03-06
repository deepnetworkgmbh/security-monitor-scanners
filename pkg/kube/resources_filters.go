package kube

import (
	corev1 "k8s.io/api/core/v1"
)

func filterNamespaces(rp *ResourceProvider, namespaces []string) {
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

func filterDeployments(rp *ResourceProvider, namespaces []string) {
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

func filterStatefulSets(rp *ResourceProvider, namespaces []string) {
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

func filterDaemonSets(rp *ResourceProvider, namespaces []string) {
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

func filterJobs(rp *ResourceProvider, namespaces []string) {
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

func filterCronJobs(rp *ResourceProvider, namespaces []string) {
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

func filterReplicationControllers(rp *ResourceProvider, namespaces []string) {
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

func filterPods(pods []corev1.Pod, namespaces []string) []corev1.Pod {
	if len(namespaces) == 0 {
		return pods
	}

	filtered := pods[:0]
	for _, x := range pods {
		for _, ns := range namespaces {
			if x.Namespace == ns {
				filtered = append(filtered, x)
			}
		}
	}
	for i := len(filtered); i < len(pods); i++ {
		pods[i] = corev1.Pod{}
	}
	return filtered
}
