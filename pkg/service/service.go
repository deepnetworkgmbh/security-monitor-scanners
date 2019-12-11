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
	scanner "github.com/deepnetworkgmbh/security-monitor-scanners/pkg/imagescanner"
	"net/http"
	"net/url"

	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/config"
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/kube"
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/validator"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// GetRouter returns a mux router serving all routes necessary for the dashboard
func GetRouter(c config.Configuration, auditPath string, port int, basePath string, auditData *validator.AuditData) *mux.Router {
	router := mux.NewRouter().PathPrefix(basePath).Subrouter()
	kubeScanner := scanner.NewScanner(c.Images.ScannerUrl)

	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	router.HandleFunc("/results.json", func(w http.ResponseWriter, r *http.Request) {
		if auditData == nil {
			k, err := kube.CreateResourceProvider(auditPath)
			if err != nil {
				logrus.Errorf("Error fetching Kubernetes resources %v", err)
				http.Error(w, "Error fetching Kubernetes resources", http.StatusInternalServerError)
				return
			}

			k.FilterByNamespace(c.NamespacesToScan...)
			auditDataObj, err := validator.RunAudit(c, k)
			if err != nil {
				http.Error(w, "Error Fetching Deployments", http.StatusInternalServerError)
				return
			}
			auditData = &auditDataObj
		}

		JSONHandler(w, auditData)
	})

	router.HandleFunc("/api/container-images/", getImageScansSummary(c, kubeScanner))

	router.HandleFunc("/api/container-image/{imageTag:.*}", getImageScanDetailsByTag(kubeScanner))

	// legacy endpoint name. Keep for backward-compatibility
	router.HandleFunc("/image/{imageTag:.*}", getImageScanDetailsByTag(kubeScanner))

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != basePath {
			http.NotFound(w, r)
			return
		}

		if auditData == nil {
			k, err := kube.CreateResourceProvider(auditPath)
			if err != nil {
				logrus.Errorf("Error fetching Kubernetes resources %v", err)
				http.Error(w, "Error fetching Kubernetes resources", http.StatusInternalServerError)
				return
			}

			k.FilterByNamespace(c.NamespacesToScan...)
			auditData, err := validator.RunAudit(c, k)
			if err != nil {
				logrus.Errorf("Error getting audit data: %v", err)
				http.Error(w, "Error running audit", 500)
				return
			}

			JSONHandler(w, auditData)
		} else {
			JSONHandler(w, auditData)
		}

	})
	return router
}

func getImageScansSummary(c config.Configuration, kubeScanner *scanner.ImageScanner) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		pods, err := kube.CreatePodsProviderFromCluster(c.NamespacesToScan...)
		if err != nil {
			logrus.Errorf("Error fetching Kubernetes resources %v", err)
			http.Error(w, "Error fetching Kubernetes resources", http.StatusInternalServerError)
			return
		}

		imageTags := kube.GetAllImageTags(pods)
		scans, err := kubeScanner.GetAll(imageTags)
		if err != nil {
			logrus.Errorf("Error fetching Image Scans %v", err)
			http.Error(w, "Error fetching Image Scans", http.StatusInternalServerError)
			return
		}

		result := CreateImageScansSummary(pods, scans)
		JSONHandler(w, result)
	}
}

func getImageScanDetailsByTag(kubeScanner *scanner.ImageScanner) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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

		JSONHandler(w, &scanResult)
	}
}

// JSONHandler gets template data and renders json with it.
func JSONHandler(w http.ResponseWriter, result interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}
