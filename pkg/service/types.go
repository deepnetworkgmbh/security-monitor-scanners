package service

import (
	"fmt"
	scanner "github.com/deepnetworkgmbh/security-monitor-scanners/pkg/imagescanner"
	corev1 "k8s.io/api/core/v1"
)

// ImageScansSummary represents a summary of container images vulnerabilities audit
type ImageScansSummary struct {
	Images []ImageScanResult `json:"images"`
}

// ImageScanResult is a short description of a single container image vulnerabilities audit
type ImageScanResult struct {
	Image       string                  `json:"image"`
	ScanResult  string                  `json:"scanResult"`
	Description string                  `json:"description"`
	Counters    []VulnerabilityCounter  `json:"counters"`
	Attributes  []string                `json:"attributes"`
	Pods        []string                `json:"pods"`
}

// VulnerabilityCounter represents amount of issues with specified severity
type VulnerabilityCounter struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

func CreateImageScansSummary(pods []corev1.Pod, scans []scanner.ImageScanResultSummary) *ImageScansSummary {
	summary := ImageScansSummary{
		Images: make([]ImageScanResult, len(scans)),
	}

	imagesSet := make(map[string]imageAttrs, len(scans))

	for i, scan := range scans {
		// init map of images. Later it would be used to map pods and labels
		imagesSet[scan.Image] = imageAttrs{
			pods:   make(map[string]bool),
			labels: make(map[string]bool),
		}

		summary.Images[i] = ImageScanResult{
			Image:       scan.Image,
			Description: scan.Description,
			ScanResult:  scan.ScanResult,
			Counters:    make([]VulnerabilityCounter, len(scan.Counters)),
		}

		for j, counter := range scan.Counters {
			summary.Images[i].Counters[j] = VulnerabilityCounter{
				Severity: counter.Severity,
				Count:    counter.Count,
			}
		}
	}

	// maps pod metadata to image scan results
	// if there is image scan result for container or init-container:
	//  - attach pod labels and namespace to set of attrs
	//  - add pod_full_name to set of pods
	for _, pod := range pods {
		for _, ic := range pod.Spec.InitContainers {
			if img, ok := imagesSet[ic.Image]; ok {
				enrichImageWithPodMetadata(&img, pod)
			}
		}
		for _, c := range pod.Spec.Containers {
			if img, ok := imagesSet[c.Image]; ok {
				enrichImageWithPodMetadata(&img, pod)
			}
		}
	}

	// use index to mutate existing object
	for i := range summary.Images {
		summary.Images[i].Attributes = getStringsFromSet(imagesSet[summary.Images[i].Image].labels)
		summary.Images[i].Pods = getStringsFromSet(imagesSet[summary.Images[i].Image].pods)
	}

	return &summary
}

type imageAttrs struct {
	pods   map[string]bool
	labels map[string]bool
}

func enrichImageWithPodMetadata(img *imageAttrs, pod corev1.Pod) {
	podFullName := fmt.Sprintf("%s.%s", pod.Namespace, pod.Name)
	img.pods[podFullName] = true

	nsAttr := fmt.Sprintf("namespace:%s", pod.Namespace)
	img.labels[nsAttr] = true

	for k, v := range pod.Labels {
		attr := fmt.Sprintf("%s:%s", k, v)
		img.labels[attr] = true
	}
}

func getStringsFromSet(set map[string]bool) []string{
	i := 0
	values := make([]string, len(set))

	for k := range set {
		values[i] = k
		i++
	}

	return values
}
