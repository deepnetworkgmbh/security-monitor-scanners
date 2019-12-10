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

		JSONHandler(w, r, &scanResult)
	})

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

			JSONHandler(w, r, auditData)
		} else {
			JSONHandler(w, r, auditData)
		}

	})
	return router
}

// JSONHandler gets template data and renders json with it.
func JSONHandler(w http.ResponseWriter, r *http.Request, auditData interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(auditData)
}
