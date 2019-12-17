package imagescanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
)

// ImageScanner base struct
type ImageScanner struct {
	ScannerURL string
}

// ImageScanResult contains details about all the found vulnerabilities
type ImageScanResult struct {
	Image       string            `json:"image"`
	ScanResult  string            `json:"scanResult"`
	Description string            `json:"description"`
	Targets     []TrivyScanTarget `json:"targets"`
}

type TrivyScanTarget struct {
	Target          string                     `json:"Target"`
	Vulnerabilities []VulnerabilityDescription `json:"Vulnerabilities"`
}

type VulnerabilityDescription struct {
	CVE              string   `json:"VulnerabilityID"`
	Package          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	References       []string `json:"References"`
}

// ImageScanResultSummary contains vulnerabilities summary
type ImageScanResultSummary struct {
	Image       string                 `json:"image"`
	ScanResult  string                 `json:"scanResult"`
	Description string                 `json:"description"`
	Counters    []VulnerabilityCounter `json:"counters"`
}

// VulnerabilityCounter represents amount of issues with specified severity
type VulnerabilityCounter struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type CveDetails struct {
	Id               string   `json:"id"`
	Package          string   `json:"packageName"`
	InstalledVersion string   `json:"installedVersion"`
	FixedVersion     string   `json:"fixedVersion"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Severity         string   `json:"severity"`
	References       []string `json:"references"`
	Images           []string `json:"imageTags"`
}

func (s *ImageScanResultSummary) GetSeverity() string {
	switch s.ScanResult {
	case "Succeeded":
		if len(s.Counters) == 0 {
			return "Success"
		} else {
			for _, counter := range s.Counters {
				if counter.Severity == "CRITICAL" || counter.Severity == "HIGH" {
					return "Error"
				}
			}

			return "Warning"
		}
	default:
		return "NoData"
	}
}

func (s *ImageScanResultSummary) GetScansMessage() string {
	switch s.ScanResult {
	case "Succeeded":
		if len(s.Counters) == 0 {
			return "The image passed vulnerabilities check"
		} else {
			message := ""

			for _, counter := range s.Counters {
				message += fmt.Sprintf("%v %v, ", counter.Count, counter.Severity)
			}

			return fmt.Sprintf("Image has %v known vulnerabilities", message[:len(message)-2])
		}
	default:
		return "No vulnerabilities check data"
	}
}

// NewScanner returns a new image-scanner instance.
func NewScanner(url string) *ImageScanner {
	return &ImageScanner{ScannerURL: url}
}

// Scan all images
func (s *ImageScanner) Scan(images []string) {
	bytesRepresentation, err := json.Marshal(images)
	scansURL := fmt.Sprintf("%s/scan/images", s.ScannerURL)

	resp, err := http.Post(scansURL, "application/json", bytes.NewBuffer(bytesRepresentation))
	if err != nil {
		logrus.Errorf("Error requesting image scan %v", err)
		return
	}

	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatal(err)
	}
	bodyString := string(bodyBytes)
	logrus.Info(bodyString)
}

// GetScanResult returns detailed single image scan result
func (s *ImageScanner) GetScanResult(image string) (scanResult ImageScanResult, err error) {
	scanResultURL := fmt.Sprintf("%s/scan-results/trivy/%s", s.ScannerURL, url.QueryEscape(image))

	resp, err := http.Get(scanResultURL)
	if err != nil {
		logrus.Errorf("Error requesting image scan result %v", err)
		return ImageScanResult{}, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&scanResult)
	if err != nil {
		logrus.Errorf("Failed to deserialize Image Scan Result: %v", err)
		return ImageScanResult{}, err
	}

	return scanResult, nil
}

// GetScanResults returns scan result summary for an array of images
func (s *ImageScanner) GetScanResults(images []string) (scanResults []ImageScanResultSummary, err error) {
	getURL := fmt.Sprintf("%s/scan-results/trivy?", s.ScannerURL)

	for _, image := range images {
		getURL = fmt.Sprintf("%s&images=%s", getURL, url.QueryEscape(image))
	}

	resp, err := http.Get(getURL)
	if err != nil {
		logrus.Errorf("Error requesting images scan results %v", err)
		return make([]ImageScanResultSummary, 0), err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&scanResults)
	if err != nil {
		logrus.Errorf("Failed to deserialize Scans Summary: %v", err)
		return make([]ImageScanResultSummary, 0), err
	}

	return scanResults, nil
}

// GetCve returns detailed cve description
func (s *ImageScanner) GetCve(id string) (details CveDetails, err error) {
	cveURL := fmt.Sprintf("%s/cve/%s", s.ScannerURL, url.QueryEscape(id))

	resp, err := http.Get(cveURL)
	if err != nil {
		logrus.Errorf("Error requesting cve details: %v", err)
		return CveDetails{}, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&details)
	if err != nil {
		logrus.Errorf("Failed to deserialize CVE details: %v", err)
		return CveDetails{}, err
	}

	return details, nil
}

// GetCveSummary returns All known CVEs summary
func (s *ImageScanner) GetCveSummary() (details []CveDetails, err error) {
	cveURL := fmt.Sprintf("%s/cve/overview", s.ScannerURL)

	resp, err := http.Get(cveURL)
	if err != nil {
		logrus.Errorf("Error requesting CVEs overview: %v", err)
		return make([]CveDetails, 0), err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&details)
	if err != nil {
		logrus.Errorf("Failed to deserialize CVE details: %v", err)
		return make([]CveDetails, 0), err
	}

	return details, nil
}

