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

type Handler struct {
	config   *config.Configuration
	basePath string
	port     int
	router   *mux.Router
	scanner  *scanner.ImageScanner
}

func NewHandler(c *config.Configuration, port int, basePath string) *Handler {
	router := mux.NewRouter().PathPrefix(basePath).Subrouter()
	kubeScanner := scanner.NewScanner(c.Images.ScannerUrl)

	h := &Handler{
		config:   c,
		basePath: basePath,
		port:     port,
		router:   router,
		scanner:  kubeScanner,
	}

	router.HandleFunc("/health", h.health)
	router.HandleFunc("/ready", h.ready)

	router.HandleFunc("/api/container-images/", h.getImageScansSummary)
	router.HandleFunc("/api/container-image/{imageTag:.*}", h.getImageScanDetailsByTag)

	// legacy endpoint name. Keep for backward-compatibility
	router.HandleFunc("/image/{imageTag:.*}", h.getImageScanDetailsByTag)
	router.HandleFunc("/", h.main)

	return h
}

func (h *Handler) GetRouter() *mux.Router {
	return h.router
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func (h *Handler) main(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != h.basePath {
		http.NotFound(w, r)
		return
	}

	k, err := kube.CreateResourceProviderFromCluster()
	if err != nil {
		logrus.Errorf("Error fetching Kubernetes resources %v", err)
		http.Error(w, "Error fetching Kubernetes resources", http.StatusInternalServerError)
		return
	}

	k.FilterByNamespace(h.config.NamespacesToScan...)
	auditData, err := validator.RunAudit(h.config, k)
	if err != nil {
		logrus.Errorf("Error getting audit data: %v", err)
		http.Error(w, "Error running audit", 500)
		return
	}

	jsonHandler(w, auditData)
}

func (h *Handler) getImageScansSummary(w http.ResponseWriter, r *http.Request) {
	pods, err := kube.CreatePodsProviderFromCluster(h.config.NamespacesToScan...)
	if err != nil {
		logrus.Errorf("Error fetching Kubernetes resources %v", err)
		http.Error(w, "Error fetching Kubernetes resources", http.StatusInternalServerError)
		return
	}

	imageTags := kube.GetAllImageTags(pods)
	scans, err := h.scanner.GetAll(imageTags)
	if err != nil {
		logrus.Errorf("Error fetching Image Scans %v", err)
		http.Error(w, "Error fetching Image Scans", http.StatusInternalServerError)
		return
	}

	result := CreateImageScansSummary(pods, scans)
	jsonHandler(w, result)
}

func (h *Handler) getImageScanDetailsByTag(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	imageTag := vars["imageTag"]

	decodedValue, err := url.QueryUnescape(imageTag)
	if err != nil {
		logrus.Error(err, "Failed to unescape", imageTag)
		return
	}

	scanResult, err := h.scanner.Get(decodedValue)
	if err != nil {
		logrus.Error(err, "Failed to get image scan details", imageTag)
		return
	}

	jsonHandler(w, &scanResult)
}

// jsonHandler gets template data and renders json with it.
func jsonHandler(w http.ResponseWriter, result interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}
