package service

import (
	"encoding/json"
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/config"
	scanner "github.com/deepnetworkgmbh/security-monitor-scanners/pkg/imagescanner"
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/kube"
	"github.com/deepnetworkgmbh/security-monitor-scanners/pkg/validator"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/url"
)

type Handler struct {
	config   *config.Config
	basePath string
	port     int
	router   *mux.Router
	scanner  *scanner.ImageScanner
}

func NewHandler(c *config.Config, port int, basePath string) *Handler {
	router := mux.NewRouter().PathPrefix(basePath).Subrouter()
	kubeScanner := scanner.NewScanner(c.Services.ScannerUrl)

	h := &Handler{
		config:   c,
		basePath: basePath,
		port:     port,
		router:   router,
		scanner:  kubeScanner,
	}

	router.Methods("GET").Path("/health").HandlerFunc(h.health)
	router.Methods("GET").Path("/ready").HandlerFunc(h.ready)

	router.Methods("GET").Path("/api/container-images/").HandlerFunc(h.getImageScansSummary)
	router.Methods("GET").Path("/api/container-image/{imageTag:.*}").HandlerFunc(h.getImageScanDetailsByTag)

	router.Methods("GET").Path("/api/kube-objects/polaris").HandlerFunc(h.getImageScanDetailsByTag)
	router.Methods("POST").Path("/api/kube-objects/polaris").HandlerFunc(h.getImageScanDetailsByTag)

	// legacy endpoint name. Keep for backward-compatibility
	router.Methods("GET").Path("/image/{imageTag:.*}").HandlerFunc(h.getImageScanDetailsByTag)
	router.Methods("GET").Path("/").HandlerFunc(h.main)

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
	k, err := kube.CreateResourceProviderFromCluster()
	if err != nil {
		logrus.Errorf("Error fetching Kubernetes resources %v", err)
		http.Error(w, "Error fetching Kubernetes resources", http.StatusInternalServerError)
		return
	}

	path, err := h.config.GetPolarisPath()
	if err != nil {
		logrus.Errorf("Error getting Polaris config %v", err)
		http.Error(w, "Error getting Polaris config", http.StatusInternalServerError)
		return
	}

	polarisConfig, err := config.ParsePolarisConfig(path)
	k.FilterByNamespace(h.config.Kube.NamespacesToScan...)
	auditData, err := validator.RunAudit(&polarisConfig, k)
	if err != nil {
		logrus.Errorf("Error getting audit data: %v", err)
		http.Error(w, "Error running audit", 500)
		return
	}

	jsonHandler(w, auditData)
}

func (h *Handler) getImageScansSummary(w http.ResponseWriter, r *http.Request) {
	pods, err := kube.CreatePodsProviderFromCluster(h.config.Kube.NamespacesToScan...)
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
