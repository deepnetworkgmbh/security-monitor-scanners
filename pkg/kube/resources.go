package kube

import (
	"time"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // Required for other auth providers like GKE.
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// ResourceProvider contains k8s resources to be audited
type ResourceProvider struct {
	ServerVersion          string
	CreationTime           time.Time
	SourceName             string
	SourceType             string
	Nodes                  []corev1.Node
	Deployments            []appsv1.Deployment
	StatefulSets           []appsv1.StatefulSet
	DaemonSets             []appsv1.DaemonSet
	Jobs                   []batchv1.Job
	CronJobs               []batchv1beta1.CronJob
	ReplicationControllers []corev1.ReplicationController
	Namespaces             []corev1.Namespace
	Pods                   []corev1.Pod
}

func GetAllImageTags(pods []corev1.Pod) []string {
	set := make(map[string]bool)
	for _, pod := range pods {
		for _, ic := range pod.Spec.InitContainers {
			set[ic.Image] = true
		}
		for _, c := range pod.Spec.Containers {
			set[c.Image] = true
		}
	}

	i := 0
	images := make([]string, len(set))

	for k := range set {
		images[i] = k
		i++
	}

	return images
}

// CreateResourceProviderFromCluster creates a new ResourceProvider using live data from a cluster
func CreateResourceProviderFromCluster() (*ResourceProvider, error) {
	kubeConf, configError := config.GetConfig()
	if configError != nil {
		logrus.Errorf("Error fetching KubeConfig %v", configError)
		return nil, configError
	}
	api, err := kubernetes.NewForConfig(kubeConf)
	if err != nil {
		logrus.Errorf("Error creating Kubernetes client %v", err)
		return nil, err
	}
	return CreateResourceProviderFromAPI(api, kubeConf.Host)
}

// CreatePodsProviderFromCluster list of pods from a cluster
func CreatePodsProviderFromCluster(namespaces ...string) ([]corev1.Pod, error) {
	kubeConf, configError := config.GetConfig()
	if configError != nil {
		logrus.Errorf("Error fetching KubeConfig %v", configError)
		return nil, configError
	}
	api, err := kubernetes.NewForConfig(kubeConf)
	if err != nil {
		logrus.Errorf("Error creating Kubernetes client %v", err)
		return nil, err
	}

	listOpts := metav1.ListOptions{}
	pods, err := api.CoreV1().Pods("").List(listOpts)
	if err != nil {
		logrus.Errorf("Error fetching Pods %v", err)
		return nil, err
	}

	return filterPods(pods.Items, namespaces), nil
}

// CreateResourceProviderFromAPI creates a new ResourceProvider from an existing k8s interface
func CreateResourceProviderFromAPI(kube kubernetes.Interface, clusterName string) (*ResourceProvider, error) {
	listOpts := metav1.ListOptions{}
	serverVersion, err := kube.Discovery().ServerVersion()
	if err != nil {
		logrus.Errorf("Error fetching Cluster API version %v", err)
		return nil, err
	}
	deploys, err := kube.AppsV1().Deployments("").List(listOpts)
	if err != nil {
		logrus.Errorf("Error fetching Deployments %v", err)
		return nil, err
	}
	statefulSets, err := kube.AppsV1().StatefulSets("").List(listOpts)
	if err != nil {
		logrus.Errorf("Error fetching StatefulSets%v", err)
		return nil, err
	}
	daemonSets, err := kube.AppsV1().DaemonSets("").List(listOpts)
	if err != nil {
		logrus.Errorf("Error fetching DaemonSets %v", err)
		return nil, err
	}
	jobs, err := kube.BatchV1().Jobs("").List(listOpts)
	if err != nil {
		logrus.Errorf("Error fetching Jobs %v", err)
		return nil, err
	}
	cronJobs, err := kube.BatchV1beta1().CronJobs("").List(listOpts)
	if err != nil {
		logrus.Errorf("Error fetching CronJobs %v", err)
		return nil, err
	}
	replicationControllers, err := kube.CoreV1().ReplicationControllers("").List(listOpts)
	if err != nil {
		logrus.Errorf("Error fetching ReplicationControllers %v", err)
		return nil, err
	}
	nodes, err := kube.CoreV1().Nodes().List(listOpts)
	if err != nil {
		logrus.Errorf("Error fetching Nodes %v", err)
		return nil, err
	}
	namespaces, err := kube.CoreV1().Namespaces().List(listOpts)
	if err != nil {
		logrus.Errorf("Error fetching Namespaces %v", err)
		return nil, err
	}
	pods, err := kube.CoreV1().Pods("").List(listOpts)
	if err != nil {
		logrus.Errorf("Error fetching Pods %v", err)
		return nil, err
	}

	api := ResourceProvider{
		ServerVersion:          serverVersion.Major + "." + serverVersion.Minor,
		SourceType:             "Cluster",
		SourceName:             clusterName,
		CreationTime:           time.Now(),
		Deployments:            deploys.Items,
		StatefulSets:           statefulSets.Items,
		DaemonSets:             daemonSets.Items,
		Jobs:                   jobs.Items,
		CronJobs:               cronJobs.Items,
		ReplicationControllers: replicationControllers.Items,
		Nodes:                  nodes.Items,
		Namespaces:             namespaces.Items,
		Pods:                   pods.Items,
	}
	return &api, nil
}

func (rp *ResourceProvider) FilterByNamespace(namespaces ...string) {
	if namespaces == nil {
		return
	}

	filterNamespaces(rp, namespaces)
	filterDeployments(rp, namespaces)
	filterStatefulSets(rp, namespaces)
	filterDaemonSets(rp, namespaces)
	filterJobs(rp, namespaces)
	filterCronJobs(rp, namespaces)
	filterReplicationControllers(rp, namespaces)
	rp.Pods = filterPods(rp.Pods, namespaces)
}
