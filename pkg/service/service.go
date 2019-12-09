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

package service

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"sort"

	scanner "github.com/deepnetworkgmbh/security-monitor-scanners/pkg/imagescanner"

	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/config"
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/kube"
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/validator"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func getConfigForQuery(base config.Configuration, query url.Values) config.Configuration {
	c := base
	exemptions := query.Get("disallowExemptions")
	if exemptions == "false" {
		c.DisallowExemptions = false
	}
	if exemptions == "true" {
		c.DisallowExemptions = true
	}
	return c
}

// GetRouter returns a mux router serving all routes necessary for the dashboard
func GetRouter(c config.Configuration, auditPath string, port int, basePath string, auditData *validator.AuditData) *mux.Router {
	router := mux.NewRouter().PathPrefix(basePath).Subrouter()
	kubeScanner := scanner.NewScanner(c.Images.ScannerUrl)

	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	router.HandleFunc("/results.json", func(w http.ResponseWriter, r *http.Request) {
		adjustedConf := getConfigForQuery(c, r.URL.Query())
		if auditData == nil {
			k, err := kube.CreateResourceProvider(auditPath)
			if err != nil {
				logrus.Errorf("Error fetching Kubernetes resources %v", err)
				http.Error(w, "Error fetching Kubernetes resources", http.StatusInternalServerError)
				return
			}

			k.FilterByNamespace(adjustedConf.NamespacesToScan...)
			auditDataObj, err := validator.RunAudit(adjustedConf, k)
			if err != nil {
				http.Error(w, "Error Fetching Deployments", http.StatusInternalServerError)
				return
			}
			auditData = &auditDataObj
		}

		JSONHandler(w, r, auditData)
	})

	router.HandleFunc("/image/{imageTag:.*}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		imageTag := vars["imageTag"]

		decodedValue, err := url.QueryUnescape(imageTag)
		if err != nil {
			logrus.Error(err, "Failed to unescape", imageTag)
			return
		}

		scanResult, err := kubeScanner.Get(decodedValue)
		if err != nil {
			logrus.Error(err, "Failed to get image scan details", imageTag)
			return
		}

		imageScanDetailsHandler(w, r, c, basePath, &scanResult)
	})

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != basePath {
			http.NotFound(w, r)
			return
		}
		adjustedConf := getConfigForQuery(c, r.URL.Query())

		if auditData == nil {
			k, err := kube.CreateResourceProvider(auditPath)
			if err != nil {
				logrus.Errorf("Error fetching Kubernetes resources %v", err)
				http.Error(w, "Error fetching Kubernetes resources", http.StatusInternalServerError)
				return
			}

			k.FilterByNamespace(adjustedConf.NamespacesToScan...)
			auditData, err := validator.RunAudit(adjustedConf, k)
			if err != nil {
				logrus.Errorf("Error getting audit data: %v", err)
				http.Error(w, "Error running audit", 500)
				return
			}
			MainHandler(w, r, adjustedConf, auditData, basePath)
		} else {
			MainHandler(w, r, adjustedConf, *auditData, basePath)
		}

	})
	return router
}

func imageScanDetailsHandler(w http.ResponseWriter, r *http.Request, c config.Configuration, basePath string, scan *scanner.ImageScanResult) {
	data := scanTemplateData{
		ImageTag:    scan.Image,
		ScanResult:  scan.ScanResult,
		Description: scan.Description,
		UsedIn:      []imageUsage{},
		ScanTargets: []imageScanTarget{},
	}

	for _, target := range scan.Targets {
		targetModel := imageScanTarget{
			Name:                  target.Target,
			VulnerabilitiesGroups: []vulnerabilitiesGroup{},
		}

		cveDict := make(map[string][]cveDetails)

		for _, cve := range target.Vulnerabilities {
			cveDict[cve.Severity] = append(cveDict[cve.Severity], cveDetails{
				Id:               cve.CVE,
				PackageName:      cve.Package,
				InstalledVersion: cve.InstalledVersion,
				FixedVersion:     cve.FixedVersion,
				Title:            cve.Title,
				Description:      cve.Description,
				References:       cve.References,
			})
		}

		keys := make([]string, 0, len(cveDict))
		for k := range cveDict {
			keys = append(keys, k)
		}
		sort.Sort(bySeverity(keys))

		for _, k := range keys {
			targetModel.VulnerabilitiesGroups = append(targetModel.VulnerabilitiesGroups, vulnerabilitiesGroup{
				Severity: k,
				Count:    len(cveDict[k]),
				CVEs:     cveDict[k],
			})
		}

		data.ScanTargets = append(data.ScanTargets, targetModel)
	}

	JSONHandler(w, r, data)
}

// MainHandler gets template data and renders the dashboard with it.
func MainHandler(w http.ResponseWriter, r *http.Request, c config.Configuration, auditData validator.AuditData, basePath string) {
	jsonData, err := json.Marshal(auditData)

	if err != nil {
		http.Error(w, "Error serializing audit data", 500)
		return
	}

	data := templateData{
		AuditData: auditData,
		JSON:      template.JS(jsonData),
	}

	JSONHandler(w, r, data)
}

// JSONHandler gets template data and renders json with it.
func JSONHandler(w http.ResponseWriter, r *http.Request, auditData interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(auditData)
}
